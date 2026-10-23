//! Detection Rule `NET-002`: High Connection-Volume Anomaly Detection with Event-Time Rolling Window.
//!
//! # Objective
//! Identifies a single source IP address producing an unusually large number of qualifying
//! connection observations within a configurable event-time rolling window.
//!
//! # Defensive Context & Snapshot Telemetry Semantics
//! **Important Operational Clarification**:
//! In Windows TCP snapshot telemetry (e.g., `GetExtendedTcpTable`), persistent or long-lived
//! TCP connections (such as database pools, continuous media streams, or HTTP/2 keep-alives)
//! are repeatedly observed across successive collection snapshot cycles.
//!
//! Because snapshot polling cannot definitively measure discrete SYN/ACK handshakes or failed
//! connection attempts without kernel event tracing (ETW), **this rule functions as an
//! observation-volume heuristic**, not a definitive failed-connection or brute-force detector.
//!
//! Legitimate causes of elevated observation volume include:
//! - Content delivery networks, video conferencing, or large file transfers with concurrent streams.
//! - Software build systems, test runners, or microservices making dense RPC queries.
//! - Database connection pools maintaining large pre-allocated socket sets.
//!
//! An alert emitted by this rule indicates an intensity spike warranting analyst inspection
//! rather than an automatic hostile compromise verdict. SentinelX enforces **no unilateral
//! host containment or network disconnection**.

use crate::engine::{DetectionError, DetectionRule};
use chrono::{DateTime, Duration, Utc};
use sentinel_core::alert::{AlertId, AlertSeverity, AlertStatus, RuleId, SecurityAlert};
use sentinel_core::error::ConfigError;
use sentinel_core::event::{EventId, NetworkEvent};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::debug;

/// Rule identifier constant for `NET-002`.
pub const RULE_ID_NET_002: &str = "NET-002";
/// Human-readable display name for `NET-002`.
pub const RULE_NAME_NET_002: &str = "High Connection-Volume Anomaly Detection";

/// Maximum allowed clock skew in the future before an event is considered invalid.
pub const MAX_FUTURE_CLOCK_SKEW: Duration = Duration::minutes(5);
/// Maximum number of distinct source IP tracking entries held in memory before evicting the oldest.
pub const MAX_TRACKED_SOURCES: usize = 10_000;
/// Maximum number of raw observations retained per source IP window.
pub const MAX_OBSERVATIONS_PER_SOURCE: usize = 2_000;

/// Configuration parameters governing `NET-002` execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionBurstConfig {
    /// Number of qualifying connection observations from a single source within the window to trigger an alert.
    pub observation_threshold: u32,
    /// Rolling window duration over event observation timestamps.
    pub window_duration: Duration,
    /// Optional cooldown duration preventing duplicate alert emission for the same source within the window.
    pub alert_cooldown: Option<Duration>,
    /// Maximum number of evidence event IDs included in an alert.
    pub max_evidence_ids_per_alert: usize,
}

impl Default for ConnectionBurstConfig {
    fn default() -> Self {
        Self {
            observation_threshold: 20,
            window_duration: Duration::seconds(60),
            alert_cooldown: Some(Duration::seconds(300)),
            max_evidence_ids_per_alert: 50,
        }
    }
}

impl ConnectionBurstConfig {
    /// Constructs a validated [`ConnectionBurstConfig`].
    ///
    /// # Errors
    /// Returns [`ConfigError`] if parameters violate constraints.
    pub fn new(
        observation_threshold: u32,
        window_duration: Duration,
        alert_cooldown: Option<Duration>,
        max_evidence_ids_per_alert: usize,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            observation_threshold,
            window_duration,
            alert_cooldown,
            max_evidence_ids_per_alert,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration parameters.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.observation_threshold == 0 {
            return Err(ConfigError::ZeroPortThreshold);
        }
        if self.window_duration <= Duration::zero() {
            return Err(ConfigError::ZeroWindowDuration);
        }
        if self.max_evidence_ids_per_alert == 0 {
            return Err(ConfigError::ZeroMaxEvidenceIds);
        }
        self.observation_threshold
            .checked_mul(4)
            .ok_or(ConfigError::ThresholdOverflow {
                description: "observation_threshold * 4 exceeds u32::MAX",
            })?;
        Ok(())
    }
}

/// Discrete observation recorded within a rolling window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservationEntry {
    timestamp: DateTime<Utc>,
    event_id: EventId,
}

/// In-memory rolling window state for a single source IP address.
#[derive(Debug, Default)]
struct SourceWindowState {
    observations: Vec<ObservationEntry>,
    last_alert_time: Option<DateTime<Utc>>,
}

/// Thread-safe in-memory rolling window tracking state across batches.
#[derive(Debug, Default)]
struct RollingState {
    sources: BTreeMap<IpAddr, SourceWindowState>,
    watermark: Option<DateTime<Utc>>,
}

/// Implementation of Rule `NET-002` detecting connection-volume anomalies.
#[derive(Debug)]
pub struct ConnectionBurstRule {
    rule_id: RuleId,
    config: ConnectionBurstConfig,
    state: Mutex<RollingState>,
}

impl ConnectionBurstRule {
    /// Creates a new `ConnectionBurstRule` with the provided configuration.
    ///
    /// # Errors
    /// Returns [`DetectionError::InvalidConfiguration`] if configuration validation fails.
    pub fn new(config: ConnectionBurstConfig) -> Result<Self, DetectionError> {
        config
            .validate()
            .map_err(DetectionError::InvalidConfiguration)?;
        let rule_id =
            RuleId::new(RULE_ID_NET_002).map_err(|e| DetectionError::RuleExecutionFailed {
                rule_id: RULE_ID_NET_002.to_string(),
                message: e.to_string(),
            })?;
        Ok(Self {
            rule_id,
            config,
            state: Mutex::new(RollingState::default()),
        })
    }

    /// Resets all in-memory rolling window state.
    ///
    /// # Panics
    /// Panics if the internal state lock is poisoned.
    pub fn reset_state(&self) {
        let mut state = self.state.lock().unwrap();
        state.sources.clear();
        state.watermark = None;
    }

    /// Returns the number of currently tracked sources.
    ///
    /// # Panics
    /// Panics if the internal state lock is poisoned.
    #[must_use]
    pub fn tracked_source_count(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.sources.len()
    }

    /// Returns the active configuration.
    #[must_use]
    pub const fn config(&self) -> &ConnectionBurstConfig {
        &self.config
    }

    /// Computes alert severity based on qualifying observation count.
    fn calculate_severity(&self, observation_count: usize) -> AlertSeverity {
        let base = self.config.observation_threshold as usize;
        let critical_multiplier = base.saturating_mul(4);
        let high_multiplier = base.saturating_mul(2);

        if observation_count >= critical_multiplier {
            AlertSeverity::Critical
        } else if observation_count >= high_multiplier {
            AlertSeverity::High
        } else {
            AlertSeverity::Medium
        }
    }
}

impl DetectionRule for ConnectionBurstRule {
    fn id(&self) -> &RuleId {
        &self.rule_id
    }

    fn name(&self) -> &str {
        RULE_NAME_NET_002
    }

    fn description(&self) -> &'static str {
        "Detects a single source IP generating an unusually high volume of connection observations across an event-time rolling window."
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate(&self, events: &[NetworkEvent]) -> Result<Vec<SecurityAlert>, DetectionError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        let now = Utc::now();
        let max_future_allowed = now + MAX_FUTURE_CLOCK_SKEW;
        let mut state_guard = self.state.lock().unwrap();

        // 1. Ingest events into rolling window state
        for event in events {
            let Some(source_ip) = event.source_ip else {
                continue;
            };

            // Discard events excessively far in the future
            if event.timestamp > max_future_allowed {
                debug!(event_id = %event.id, timestamp = %event.timestamp, "Discarding event with excessive future clock skew");
                continue;
            }

            // Update watermark
            let new_watermark = match state_guard.watermark {
                Some(w) => w.max(event.timestamp),
                None => event.timestamp,
            };
            state_guard.watermark = Some(new_watermark);

            // Discard late-arriving events outside active window
            let window_cutoff = new_watermark - self.config.window_duration;
            if event.timestamp < window_cutoff {
                debug!(event_id = %event.id, timestamp = %event.timestamp, "Discarding late event outside active window");
                continue;
            }

            // Bounded tracked sources check: evict the source with the oldest activity if full
            if !state_guard.sources.contains_key(&source_ip)
                && state_guard.sources.len() >= MAX_TRACKED_SOURCES
            {
                let oldest_source = state_guard
                    .sources
                    .iter()
                    .min_by_key(|(_ip, src)| {
                        src.observations
                            .last()
                            .map(|o| o.timestamp)
                            .or(src.last_alert_time)
                            .unwrap_or(DateTime::<Utc>::MIN_UTC)
                    })
                    .map(|(ip, _)| *ip);
                if let Some(evict_ip) = oldest_source {
                    state_guard.sources.remove(&evict_ip);
                }
            }

            let source_state = state_guard.sources.entry(source_ip).or_default();

            // Deduplicate identical event IDs
            if source_state
                .observations
                .iter()
                .any(|obs| obs.event_id == event.id)
            {
                continue;
            }

            // Insert in chronological order
            let insert_pos = source_state
                .observations
                .partition_point(|obs| obs.timestamp <= event.timestamp);
            source_state.observations.insert(
                insert_pos,
                ObservationEntry {
                    timestamp: event.timestamp,
                    event_id: event.id,
                },
            );

            // Bound per-source observation history
            if source_state.observations.len() > MAX_OBSERVATIONS_PER_SOURCE {
                source_state.observations.remove(0);
            }
        }

        let Some(watermark) = state_guard.watermark else {
            return Ok(Vec::new());
        };
        let window_cutoff = watermark - self.config.window_duration;
        let cooldown_dur = self.config.alert_cooldown;

        // 2. Prune expired observations outside the active window, preserving active cooldowns
        state_guard.sources.retain(|_ip, src_state| {
            src_state
                .observations
                .retain(|obs| obs.timestamp >= window_cutoff);
            let in_cooldown = match (src_state.last_alert_time, cooldown_dur) {
                (Some(last_alert), Some(cd)) => watermark < last_alert + cd,
                _ => false,
            };
            !src_state.observations.is_empty() || in_cooldown
        });

        // 3. Evaluate detection criteria deterministically for each source IP
        let mut alerts = Vec::new();
        let threshold = self.config.observation_threshold as usize;

        for (&source_ip, src_state) in &mut state_guard.sources {
            let observation_count = src_state.observations.len();
            if observation_count >= threshold {
                // Cooldown check
                if let (Some(last_alert), Some(cooldown)) =
                    (src_state.last_alert_time, self.config.alert_cooldown)
                    && watermark < last_alert + cooldown
                {
                    debug!(
                        source_ip = %source_ip,
                        last_alert = %last_alert,
                        "NET-002 alert suppressed due to active cooldown window"
                    );
                    continue;
                }

                src_state.last_alert_time = Some(watermark);

                let severity = self.calculate_severity(observation_count);
                let title = format!(
                    "High Connection-Volume Anomaly from {source_ip} ({observation_count} observations)"
                );

                let first_seen = src_state
                    .observations
                    .first()
                    .map_or(watermark, |o| o.timestamp);
                let last_seen = src_state
                    .observations
                    .last()
                    .map_or(watermark, |o| o.timestamp);

                let evidence_ids: Vec<EventId> = src_state
                    .observations
                    .iter()
                    .take(self.config.max_evidence_ids_per_alert)
                    .map(|o| o.event_id)
                    .collect();

                let explanation = format!(
                    "Source IP {source_ip} produced {observation_count} qualifying connection observations \
                    (threshold: {threshold}) within a {win_secs}s event-time window. \
                    Note: In snapshot telemetry (e.g. Windows TCP table polling), persistent connections \
                    are repeatedly sampled. This rule serves as an observation-volume heuristic rather than \
                    a confirmed connection-attempt or brute-force failure detector.",
                    win_secs = self.config.window_duration.num_seconds()
                );

                let alert = SecurityAlert {
                    id: AlertId::new(),
                    rule_id: self.rule_id.clone(),
                    severity,
                    title,
                    explanation,
                    first_observed_at: first_seen,
                    last_observed_at: last_seen,
                    observation_count,
                    source_ip: Some(source_ip),
                    evidence_event_ids: evidence_ids,
                    status: AlertStatus::Open,
                };

                alert.validate().map_err(DetectionError::Domain)?;
                alerts.push(alert);
            }
        }

        Ok(alerts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::event::{NetworkEventBuilder, NetworkProtocol, TelemetrySource};
    use std::net::Ipv4Addr;

    fn make_test_event(src_ip: Option<IpAddr>, ts_offset_secs: i64) -> NetworkEvent {
        let base_time = Utc::now() + Duration::seconds(ts_offset_secs);
        NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            base_time,
        )
        .with_opt_source_ip(src_ip)
        .with_destination_port(80)
        .build()
        .expect("valid test event")
    }

    #[test]
    fn test_connection_burst_threshold_trigger() {
        let config = ConnectionBurstConfig::new(5, Duration::seconds(60), None, 10).unwrap();
        let rule = ConnectionBurstRule::new(config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100));
        let events: Vec<NetworkEvent> = (0..5).map(|i| make_test_event(Some(ip), i)).collect();

        let alerts = rule.evaluate(&events).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id.as_str(), RULE_ID_NET_002);
        assert_eq!(alerts[0].observation_count, 5);
        assert_eq!(alerts[0].severity, AlertSeverity::Medium);
    }

    #[test]
    fn test_repeated_snapshots_deduplication() {
        let config = ConnectionBurstConfig::new(5, Duration::seconds(60), None, 10).unwrap();
        let rule = ConnectionBurstRule::new(config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 101));
        let e1 = make_test_event(Some(ip), 0);
        let e2 = make_test_event(Some(ip), 1);

        // Same two events delivered 4 times across repeated snapshots:
        let batch: Vec<NetworkEvent> = vec![e1.clone(), e2.clone(), e1.clone(), e2.clone()];
        let alerts = rule.evaluate(&batch).unwrap();
        // Only 2 distinct event IDs, which is below threshold of 5:
        assert!(
            alerts.is_empty(),
            "duplicate event IDs must not inflate count"
        );
    }

    #[test]
    fn test_out_of_order_events() {
        let config = ConnectionBurstConfig::new(3, Duration::seconds(60), None, 10).unwrap();
        let rule = ConnectionBurstRule::new(config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 102));
        // Delivered in reverse: t=30, t=20, t=10
        let events = vec![
            make_test_event(Some(ip), 30),
            make_test_event(Some(ip), 20),
            make_test_event(Some(ip), 10),
        ];

        let alerts = rule.evaluate(&events).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].observation_count, 3);
    }

    #[test]
    fn test_window_state_expiration() {
        let config = ConnectionBurstConfig::new(4, Duration::seconds(10), None, 10).unwrap();
        let rule = ConnectionBurstRule::new(config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 103));

        // Batch 1 at t=0: 2 events
        let b1 = vec![make_test_event(Some(ip), 0), make_test_event(Some(ip), 1)];
        assert!(rule.evaluate(&b1).unwrap().is_empty());

        // Batch 2 at t=25 (15s later, window is 10s): 2 events
        let b2 = vec![make_test_event(Some(ip), 24), make_test_event(Some(ip), 25)];
        // Total in active window is 2, not 4:
        assert!(
            rule.evaluate(&b2).unwrap().is_empty(),
            "expired events must not contribute to threshold"
        );
    }

    #[test]
    fn test_severity_scaling() {
        let config = ConnectionBurstConfig::new(5, Duration::seconds(60), None, 50).unwrap();
        let rule = ConnectionBurstRule::new(config).unwrap();

        assert_eq!(rule.calculate_severity(5), AlertSeverity::Medium);
        assert_eq!(rule.calculate_severity(9), AlertSeverity::Medium);
        assert_eq!(rule.calculate_severity(10), AlertSeverity::High);
        assert_eq!(rule.calculate_severity(19), AlertSeverity::High);
        assert_eq!(rule.calculate_severity(20), AlertSeverity::Critical);
    }
}
