//! Detection engine orchestration, rule abstractions, and batch processing.
//!
//! # Engine Responsibilities
//! The [`DetectionEngine`] coordinates the execution of registered [`DetectionRule`] implementations
//! against bounded batches of normalized [`NetworkEvent`] observations.
//!
//! Key design guarantees:
//! - **Decoupled**: Completely isolated from concrete network collectors, operating system APIs,
//!   databases, and user interfaces.
//! - **Deterministic**: Identical inputs and configurations produce identical alerts in stable,
//!   predictable order.
//! - **Fault-Tolerant**: Never panics on empty or malformed inputs.
//! - **Bounded**: Enforces batch size limits to protect against unbounded resource consumption.

use sentinel_core::alert::{RuleId, SecurityAlert};
use sentinel_core::config::DetectionConfig;
use sentinel_core::error::{ConfigError, DomainError};
use sentinel_core::event::NetworkEvent;
use std::fmt;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

/// Errors encountered during detection engine operation and rule evaluation.
#[derive(Debug, Error)]
pub enum DetectionError {
    /// Ingestion batch exceeds configured maximum allowed size.
    #[error("batch size {size} exceeds maximum permitted batch limit of {max}")]
    BatchSizeExceeded {
        /// Number of events in the submitted batch.
        size: usize,
        /// Maximum allowed batch size.
        max: usize,
    },

    /// Invalid engine or rule configuration.
    #[error("detection configuration error: {0}")]
    InvalidConfiguration(#[from] ConfigError),

    /// A detection rule failed during execution.
    #[error("rule '{rule_id}' failed execution: {message}")]
    RuleExecutionFailed {
        /// Rule ID of the failing rule.
        rule_id: String,
        /// Diagnostic error message.
        message: String,
    },

    /// Domain invariant violation when constructing an alert.
    #[error("domain violation: {0}")]
    Domain(#[from] DomainError),
}

/// Abstract contract for a pluggable cybersecurity detection rule.
///
/// Rules evaluate a batch of normalized network events and emit any generated security alerts.
pub trait DetectionRule: Send + Sync + fmt::Debug {
    /// Returns the unique rule identifier (e.g., `NET-001`).
    fn id(&self) -> &RuleId;

    /// Returns the human-readable display name of the rule.
    fn name(&self) -> &str;

    /// Returns a short technical description of what the rule detects.
    fn description(&self) -> &'static str;

    /// Evaluates the provided batch of network events and produces security alerts.
    ///
    /// # Errors
    /// Returns [`DetectionError`] if rule evaluation encounters an unrecoverable failure.
    fn evaluate(&self, events: &[NetworkEvent]) -> Result<Vec<SecurityAlert>, DetectionError>;
}

/// Core detection engine orchestrating rule evaluation across bounded event batches.
pub struct DetectionEngine {
    config: DetectionConfig,
    rules: Vec<Box<dyn DetectionRule>>,
}

impl fmt::Debug for DetectionEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectionEngine")
            .field("config", &self.config)
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

impl DetectionEngine {
    /// Initializes a new [`DetectionEngine`] with the given configuration.
    ///
    /// # Errors
    /// Returns [`DetectionError::InvalidConfiguration`] if configuration invariants are violated.
    pub fn new(config: DetectionConfig) -> Result<Self, DetectionError> {
        config
            .validate()
            .map_err(DetectionError::InvalidConfiguration)?;
        Ok(Self {
            config,
            rules: Vec::new(),
        })
    }

    /// Adds a detection rule to the engine.
    pub fn add_rule(&mut self, rule: Box<dyn DetectionRule>) {
        info!(rule_id = %rule.id(), rule_name = %rule.name(), "Registering detection rule");
        self.rules.push(rule);
    }

    /// Fluent builder method to attach a rule.
    #[must_use]
    pub fn with_rule(mut self, rule: Box<dyn DetectionRule>) -> Self {
        self.add_rule(rule);
        self
    }

    /// Returns the active detection configuration.
    #[must_use]
    pub const fn config(&self) -> &DetectionConfig {
        &self.config
    }

    /// Returns the count of registered detection rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Processes a batch of normalized network events across all registered rules.
    ///
    /// Returns a vector of generated [`SecurityAlert`] instances sorted in deterministic order.
    ///
    /// # Errors
    /// Returns [`DetectionError::BatchSizeExceeded`] if `events.len() > config.max_batch_size`,
    /// or other errors propagated by failing detection rules.
    #[instrument(skip(self, events), fields(event_count = events.len()))]
    pub fn process_batch(
        &self,
        events: &[NetworkEvent],
    ) -> Result<Vec<SecurityAlert>, DetectionError> {
        if events.len() > self.config.max_batch_size {
            warn!(
                batch_size = events.len(),
                max_batch = self.config.max_batch_size,
                "Batch size exceeded configured threshold"
            );
            return Err(DetectionError::BatchSizeExceeded {
                size: events.len(),
                max: self.config.max_batch_size,
            });
        }

        if events.is_empty() {
            debug!("Empty batch received; returning 0 alerts");
            return Ok(Vec::new());
        }

        let mut aggregated_alerts = Vec::new();

        for rule in &self.rules {
            debug!(rule_id = %rule.id(), "Evaluating rule against batch");
            let mut rule_alerts = rule.evaluate(events)?;
            debug!(
                rule_id = %rule.id(),
                alert_count = rule_alerts.len(),
                "Rule evaluation complete"
            );
            aggregated_alerts.append(&mut rule_alerts);
        }

        // Sort alerts deterministically for reproducible ordering.
        // Order key: (source_ip, rule_id, first_observed_at, alert_id)
        aggregated_alerts.sort_by(|a, b| {
            a.source_ip
                .cmp(&b.source_ip)
                .then_with(|| a.rule_id.as_str().cmp(b.rule_id.as_str()))
                .then_with(|| a.first_observed_at.cmp(&b.first_observed_at))
                .then_with(|| a.id.cmp(&b.id))
        });

        info!(
            total_alerts = aggregated_alerts.len(),
            "Batch processing finished successfully"
        );
        Ok(aggregated_alerts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::PortScanRule;
    use chrono::Utc;
    use sentinel_core::event::{NetworkEventBuilder, NetworkProtocol, TelemetrySource};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_engine_empty_batch() {
        let config = DetectionConfig::default();
        let engine = DetectionEngine::new(config).expect("valid engine");
        let alerts = engine.process_batch(&[]).expect("empty batch succeeds");
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_engine_batch_limit_exceeded() {
        let mut config = DetectionConfig::default();
        config.max_batch_size = 2;
        let engine = DetectionEngine::new(config).expect("valid engine");

        let now = Utc::now();
        let make_event = || {
            NetworkEventBuilder::new(
                TelemetrySource::SyntheticSimulator,
                NetworkProtocol::Tcp,
                now,
            )
            .build()
            .unwrap()
        };
        let batch = vec![make_event(), make_event(), make_event()]; // 3 events > max 2

        let err = engine.process_batch(&batch).unwrap_err();
        assert!(matches!(
            err,
            DetectionError::BatchSizeExceeded { size: 3, max: 2 }
        ));
    }

    #[test]
    fn test_engine_with_port_scan_rule() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 2;
        let rule = PortScanRule::new(config.clone()).unwrap();
        let engine = DetectionEngine::new(config)
            .unwrap()
            .with_rule(Box::new(rule));

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100));
        let now = Utc::now();
        let events = vec![
            NetworkEventBuilder::new(
                TelemetrySource::SyntheticSimulator,
                NetworkProtocol::Tcp,
                now,
            )
            .with_source_ip(ip)
            .with_destination_port(80)
            .build()
            .unwrap(),
            NetworkEventBuilder::new(
                TelemetrySource::SyntheticSimulator,
                NetworkProtocol::Tcp,
                now,
            )
            .with_source_ip(ip)
            .with_destination_port(443)
            .build()
            .unwrap(),
        ];

        let alerts = engine.process_batch(&events).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].source_ip, Some(ip));
    }
}
