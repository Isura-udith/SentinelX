//! Detection engine and rule configuration models, default parameters, and threshold validation.
//!
//! # Operational Defaults Disclaimer
//! The default thresholds provided herein (e.g., distinct port threshold of 10) are
//! **demonstration and testing baseline values**, designed for localized lab verification
//! and synthetic data evaluation.
//!
//! **They do not represent universal cybersecurity standards.**
//! Real-world enterprise environments vary dramatically: a developer workstation running
//! microservices or local containers routinely contacts dozens of local ports legitimately,
//! whereas a locked-down domain controller doing so may be immediately anomalous.
//! Security operations teams must baseline their specific network segment profiles before
//! deploying rules to production.

use crate::error::ConfigError;
use chrono::Duration;
use serde::{Deserialize, Serialize};

/// Configuration parameters governing detection engine execution and rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Number of distinct destination ports observed from a single source required to trigger an alert.
    ///
    /// Must be greater than zero.
    pub distinct_port_threshold: u16,

    /// Observation time window duration during which port counts are tracked.
    ///
    /// Must be strictly positive.
    pub window_duration: Duration,

    /// Optional cooldown duration preventing duplicate alert emission for the same source within the window.
    pub alert_cooldown: Option<Duration>,

    /// Maximum number of connection observations accepted in a single processing batch.
    ///
    /// Protects against memory exhaustion and unbounded ingestion latency. Must be greater than zero.
    pub max_batch_size: usize,

    /// Maximum number of supporting evidence event IDs preserved in an alert object.
    ///
    /// Prevents unbounded alert payload memory inflation during high-volume reconnaissance.
    /// Must be greater than zero.
    pub max_evidence_ids_per_alert: usize,
}

impl DetectionConfig {
    /// Constructs a new [`DetectionConfig`] and validates all threshold and arithmetic constraints.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if any parameter is zero or if threshold arithmetic overflows.
    pub fn new(
        distinct_port_threshold: u16,
        window_duration: Duration,
        alert_cooldown: Option<Duration>,
        max_batch_size: usize,
        max_evidence_ids_per_alert: usize,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            distinct_port_threshold,
            window_duration,
            alert_cooldown,
            max_batch_size,
            max_evidence_ids_per_alert,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration values and verifies checked arithmetic boundaries.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if invariants are violated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.distinct_port_threshold == 0 {
            return Err(ConfigError::ZeroPortThreshold);
        }

        if self.window_duration <= Duration::zero() {
            return Err(ConfigError::ZeroWindowDuration);
        }

        if self.max_batch_size == 0 {
            return Err(ConfigError::ZeroBatchSize);
        }

        if self.max_evidence_ids_per_alert == 0 {
            return Err(ConfigError::ZeroMaxEvidenceIds);
        }

        // Validate checked arithmetic for severity threshold scaling (multipliers 2 and 4).
        // If distinct_port_threshold * 4 would overflow u16, we reject configuration.
        self.distinct_port_threshold
            .checked_mul(4)
            .ok_or(ConfigError::ThresholdOverflow {
                description: "distinct_port_threshold * 4 (critical severity scale) exceeds u16::MAX",
            })?;

        Ok(())
    }
}

impl Default for DetectionConfig {
    /// Provides baseline demonstration defaults.
    ///
    /// - `distinct_port_threshold`: 10 distinct ports
    /// - `window_duration`: 60 seconds
    /// - `alert_cooldown`: 300 seconds (5 minutes)
    /// - `max_batch_size`: 10,000 events
    /// - `max_evidence_ids_per_alert`: 50 event IDs
    fn default() -> Self {
        Self {
            distinct_port_threshold: 10,
            window_duration: Duration::seconds(60),
            alert_cooldown: Some(Duration::seconds(300)),
            max_batch_size: 10_000,
            max_evidence_ids_per_alert: 50,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = DetectionConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_zero_threshold_rejected() {
        let config = DetectionConfig {
            distinct_port_threshold: 0,
            ..Default::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::ZeroPortThreshold
        );
    }

    #[test]
    fn test_zero_or_negative_window_rejected() {
        let config_zero = DetectionConfig {
            window_duration: Duration::zero(),
            ..Default::default()
        };
        assert_eq!(
            config_zero.validate().unwrap_err(),
            ConfigError::ZeroWindowDuration
        );

        let config_neg = DetectionConfig {
            window_duration: Duration::seconds(-5),
            ..Default::default()
        };
        assert_eq!(
            config_neg.validate().unwrap_err(),
            ConfigError::ZeroWindowDuration
        );
    }

    #[test]
    fn test_zero_batch_size_rejected() {
        let config = DetectionConfig {
            max_batch_size: 0,
            ..Default::default()
        };
        assert_eq!(config.validate().unwrap_err(), ConfigError::ZeroBatchSize);
    }

    #[test]
    fn test_zero_evidence_ids_rejected() {
        let config = DetectionConfig {
            max_evidence_ids_per_alert: 0,
            ..Default::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigError::ZeroMaxEvidenceIds
        );
    }

    #[test]
    fn test_threshold_arithmetic_overflow_rejected() {
        let config = DetectionConfig {
            distinct_port_threshold: 20_000,
            ..Default::default()
        };
        assert!(matches!(
            config.validate().unwrap_err(),
            ConfigError::ThresholdOverflow { .. }
        ));
    }
}
