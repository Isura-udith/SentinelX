//! Detection Rule `NET-001`: Port-Scan-Like Activity Detection with Event-Time Rolling Window.
//!
//! # Objective
//! Identifies a single source IP address that attempts or establishes connections to an
//! unusual number of distinct destination ports across an event-time rolling window.
//!
//! # Defensive Context & False Positive Guidance
//! Port sweep and scan patterns are classic indicators of automated reconnaissance (e.g.,
//! network mapping, vulnerability scanning, worm propagation). However, identical patterns
//! are routinely produced by:
//! - Authorized enterprise vulnerability scanners and compliance audit tools.
//! - Administrative network discovery scripts.
//! - High-concurrency peer-to-peer applications or developer service meshes.
//! - Network monitoring agents probing local listening daemons.
//!
//! **Important Operational Boundary**:
//! An alert emitted by this rule constitutes a **detection signal for triage**, not definitive
//! proof of hostile compromise. SentinelX strictly refrains from automated containment
//! (such as firewall blocks or host isolation) to prevent inadvertent denial of service
//! against legitimate administrative operations.
//!
//! # Event-Time Rolling Window Semantics
//! - Window evaluation is driven by observation timestamps (`event.timestamp`), not wall-clock arrival time.
//! - Events arriving out-of-order within the window are inserted into sorted order.
//! - Observations older than `window_duration` relative to the current watermark are purged.
//! - Events with future timestamps exceeding 5 minutes clock skew are discarded.
//! - Duplicate `EventId` deliveries are recognized and ignored idempotently.
//! - Repeated observations of the same destination port are counted toward total observations
//!   but **never** inflate the distinct destination port count.
//! - Inactive source tracking states are bounded to prevent memory exhaustion.

use crate::engine::{DetectionError, DetectionRule};
use chrono::{DateTime, Duration, Utc};
use sentinel_core::alert::{AlertId, AlertSeverity, AlertStatus, RuleId, SecurityAlert};
use sentinel_core::config::DetectionConfig;
use sentinel_core::event::{EventId, NetworkEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::debug;

/// Rule identifier constant for `NET-001`.
pub const RULE_ID_NET_001: &str = "NET-001";
/// Human-readable name for `NET-001`.
pub const RULE_NAME_NET_001: &str = "Port-Scan-Like Activity Detection";

/// Maximum allowed clock skew in the future before an event is considered malformed/invalid.
pub const MAX_FUTURE_CLOCK_SKEW: Duration = Duration::minutes(5);
/// Maximum number of distinct source IP tracking entries held in memory before evicting the oldest.
pub const MAX_TRACKED_SOURCES: usize = 10_000;
/// Maximum number of raw observations retained per source IP window.
pub const MAX_OBSERVATIONS_PER_SOURCE: usize = 1_000;

/// Discrete port observation recorded within a rolling window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PortObservation {
    timestamp: DateTime<Utc>,
    event_id: EventId,
    destination_port: u16,
}

/// In-memory rolling window state for a single source IP address.
#[derive(Debug, Default)]
struct SourceWindowState {
    observations: Vec<PortObservation>,
    last_alert_time: Option<DateTime<Utc>>,
}

/// Thread-safe in-memory rolling window tracking state across batches.
#[derive(Debug, Default)]
struct RollingState {
    sources: BTreeMap<IpAddr, SourceWindowState>,
    watermark: Option<DateTime<Utc>>,
}

/// Implementation of Rule `NET-001` with stateful event-time rolling window analysis.
#[derive(Debug)]
pub struct PortScanRule {
    rule_id: RuleId,
    config: DetectionConfig,
    state: Mutex<RollingState>,
}

impl PortScanRule {
    /// Creates a new `PortScanRule` configured with the provided detection settings.
    ///
    /// # Errors
    /// Returns [`DetectionError::InvalidConfiguration`] if configuration validation fails.
    pub fn new(config: DetectionConfig) -> Result<Self, DetectionError> {
        config
            .validate()
            .map_err(DetectionError::InvalidConfiguration)?;
        let rule_id =
            RuleId::new(RULE_ID_NET_001).map_err(|e| DetectionError::RuleExecutionFailed {
                rule_id: RULE_ID_NET_001.to_string(),
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

    /// Determines the appropriate [`AlertSeverity`] based on distinct port count using checked arithmetic.
    fn calculate_severity(&self, distinct_port_count: usize) -> AlertSeverity {
        let base_threshold = self.config.distinct_port_threshold as usize;
        let critical_multiplier = base_threshold.saturating_mul(4);
        let high_multiplier = base_threshold.saturating_mul(2);

        if distinct_port_count >= critical_multiplier {
            AlertSeverity::Critical
        } else if distinct_port_count >= high_multiplier {
            AlertSeverity::High
        } else {
            AlertSeverity::Medium
        }
    }
}

impl DetectionRule for PortScanRule {
    fn id(&self) -> &RuleId {
        &self.rule_id
    }

    fn name(&self) -> &str {
        RULE_NAME_NET_001
    }

    fn description(&self) -> &'static str {
        "Detects a single source IP contacting an unusual count of distinct destination ports across an event-time rolling window."
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
            // Documented policy: events missing source_ip or destination_port are skipped.
            let (Some(source_ip), Some(dest_port)) = (event.source_ip, event.destination_port)
            else {
                continue;
            };

            // Clock skew check: ignore events ridiculously far in the future
            if event.timestamp > max_future_allowed {
                debug!(event_id = %event.id, timestamp = %event.timestamp, "Discarding event with excessive future clock skew");
                continue;
            }

            // Update watermark to the latest valid event timestamp observed
            let new_watermark = match state_guard.watermark {
                Some(w) => w.max(event.timestamp),
                None => event.timestamp,
            };
            state_guard.watermark = Some(new_watermark);

            // Discard late-arriving events that fall completely outside the active window + grace period
            let window_cutoff = new_watermark - self.config.window_duration;
            if event.timestamp < window_cutoff {
                debug!(event_id = %event.id, timestamp = %event.timestamp, "Discarding late-arriving event outside active window");
                continue;
            }

            // Check bounded source count: evict the source with the oldest activity if full
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

            // Deduplicate: check if event_id already received
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
                PortObservation {
                    timestamp: event.timestamp,
                    event_id: event.id,
                    destination_port: dest_port,
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
        let threshold = self.config.distinct_port_threshold as usize;

        for (&source_ip, src_state) in &mut state_guard.sources {
            // Count distinct destination ports
            let mut distinct_ports = BTreeSet::new();
            let mut evidence_ids = Vec::with_capacity(self.config.max_evidence_ids_per_alert);
            let mut first_seen = watermark;
            let mut last_seen = window_cutoff;

            for obs in &src_state.observations {
                distinct_ports.insert(obs.destination_port);
                if evidence_ids.len() < self.config.max_evidence_ids_per_alert
                    && !evidence_ids.contains(&obs.event_id)
                {
                    evidence_ids.push(obs.event_id);
                }
                if obs.timestamp < first_seen {
                    first_seen = obs.timestamp;
                }
                if obs.timestamp > last_seen {
                    last_seen = obs.timestamp;
                }
            }

            let distinct_count = distinct_ports.len();
            if distinct_count >= threshold {
                // Check cooldown suppression
                if let (Some(last_alert), Some(cooldown)) =
                    (src_state.last_alert_time, self.config.alert_cooldown)
                    && watermark < last_alert + cooldown
                {
                    debug!(
                        source_ip = %source_ip,
                        last_alert = %last_alert,
                        "Alert suppressed due to active cooldown window"
                    );
                    continue;
                }

                src_state.last_alert_time = Some(watermark);

                let severity = self.calculate_severity(distinct_count);
                let title = format!(
                    "Port-Scan-Like Activity from {source_ip} ({distinct_count} distinct destination ports)"
                );

                let sampled_ports: Vec<String> = distinct_ports
                    .iter()
                    .take(8)
                    .map(ToString::to_string)
                    .collect();
                let port_sample_str = sampled_ports.join(", ");
                let more_indicator = if distinct_count > 8 {
                    format!(" and {} more", distinct_count - 8)
                } else {
                    String::new()
                };

                let total_observations = src_state.observations.len();
                let explanation = format!(
                    "Source IP {source_ip} contacted {distinct_count} distinct destination ports \
                    (threshold: {threshold}) across {total_observations} total connection observations \
                    within a {win_secs}s event-time window. Sampled target ports: [{port_sample_str}{more_indicator}]. \
                    Note: This alert represents an analytical detection signal for defensive triage. \
                    Legitimate network vulnerability scanners or diagnostic tools may produce similar patterns.",
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
                    observation_count: total_observations,
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

    fn make_test_event(
        src_ip: Option<IpAddr>,
        dst_port: Option<u16>,
        ts_offset_secs: i64,
    ) -> NetworkEvent {
        let base_time = Utc::now() + Duration::seconds(ts_offset_secs);
        NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            base_time,
        )
        .with_opt_source_ip(src_ip)
        .with_opt_destination_port(dst_port)
        .build()
        .expect("valid test event")
    }

    #[test]
    fn test_port_scan_rule_detection_success() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let events = vec![
            make_test_event(Some(ip), Some(80), 0),
            make_test_event(Some(ip), Some(443), 1),
            make_test_event(Some(ip), Some(8080), 2),
        ];

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.rule_id.as_str(), RULE_ID_NET_001);
        assert_eq!(alert.source_ip, Some(ip));
        assert_eq!(alert.severity, AlertSeverity::Medium);
        assert_eq!(alert.observation_count, 3);
        assert_eq!(alert.evidence_event_ids.len(), 3);
    }

    #[test]
    fn test_duplicate_ports_do_not_inflate_count() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        let events: Vec<NetworkEvent> = (0..10)
            .map(|i| make_test_event(Some(ip), Some(443), i))
            .collect();

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_duplicate_event_ids_ignored() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 25));
        let e1 = make_test_event(Some(ip), Some(80), 0);
        let e2 = make_test_event(Some(ip), Some(443), 1);

        // Submit e1 and e2 twice:
        let batch1 = vec![e1.clone(), e2.clone()];
        let alerts1 = rule.evaluate(&batch1).unwrap();
        assert!(alerts1.is_empty()); // 2 distinct ports < 3

        let batch2 = vec![e1.clone(), e2.clone()];
        let alerts2 = rule.evaluate(&batch2).unwrap();
        // Duplicates must not inflate count:
        assert!(alerts2.is_empty());
    }

    #[test]
    fn test_out_of_order_events_handled() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        config.window_duration = Duration::seconds(60);
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 26));
        // Deliver in reverse order: t=20, t=10, t=0
        let events = vec![
            make_test_event(Some(ip), Some(8080), 20),
            make_test_event(Some(ip), Some(443), 10),
            make_test_event(Some(ip), Some(80), 0),
        ];

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].observation_count, 3);
        assert_eq!(alerts[0].evidence_event_ids.len(), 3);
    }

    #[test]
    fn test_rolling_window_expiration() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        config.window_duration = Duration::seconds(10); // 10 second window
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 27));

        // Batch 1 at t=0: ports 80 and 443 (2 distinct ports < 3)
        let b1 = vec![
            make_test_event(Some(ip), Some(80), 0),
            make_test_event(Some(ip), Some(443), 1),
        ];
        let a1 = rule.evaluate(&b1).unwrap();
        assert!(a1.is_empty());

        // Batch 2 at t=25 (15 seconds after window expired!): port 8080
        // Window covers [15..25], so ports 80 and 443 at t=0,1 are expired!
        let b2 = vec![make_test_event(Some(ip), Some(8080), 25)];
        let a2 = rule.evaluate(&b2).unwrap();
        assert!(a2.is_empty(), "expired observations must not contribute");
    }

    #[test]
    fn test_alert_cooldown() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 2;
        config.window_duration = Duration::seconds(60);
        config.alert_cooldown = Some(Duration::seconds(30));
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 28));

        // Batch 1: triggers alert
        let b1 = vec![
            make_test_event(Some(ip), Some(80), 0),
            make_test_event(Some(ip), Some(443), 1),
        ];
        let a1 = rule.evaluate(&b1).unwrap();
        assert_eq!(a1.len(), 1);

        // Batch 2 at t=5 (within 30s cooldown): new port 8080
        let b2 = vec![make_test_event(Some(ip), Some(8080), 5)];
        let a2 = rule.evaluate(&b2).unwrap();
        assert!(a2.is_empty(), "must be suppressed during cooldown");

        // Batch 3 at t=35 (after 30s cooldown): new port 9000
        let b3 = vec![make_test_event(Some(ip), Some(9000), 35)];
        let a3 = rule.evaluate(&b3).unwrap();
        assert_eq!(a3.len(), 1, "alert permitted after cooldown expires");
    }

    #[test]
    fn test_future_clock_skew_rejected() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 2;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 29));
        // Event 10 hours in the future (exceeds 5 minute limit)
        let future_event = make_test_event(Some(ip), Some(80), 36000);
        let normal_event = make_test_event(Some(ip), Some(443), 0);

        let alerts = rule.evaluate(&[future_event, normal_event]).unwrap();
        // Only normal event counted (1 < 2), future event ignored:
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_multiple_source_addresses_isolated() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 32));

        let events = vec![
            make_test_event(Some(ip_a), Some(80), 0),
            make_test_event(Some(ip_a), Some(443), 1),
            make_test_event(Some(ip_b), Some(22), 2),
            make_test_event(Some(ip_b), Some(25), 3),
        ];

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_empty_input_produces_no_alerts() {
        let rule = PortScanRule::new(DetectionConfig::default()).expect("rule creation");
        let alerts = rule.evaluate(&[]).expect("evaluation succeeds");
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_missing_fields_gracefully_ignored() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 2;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40));
        let events = vec![
            make_test_event(None, Some(80), 0),
            make_test_event(Some(ip), None, 1),
            make_test_event(Some(ip), Some(80), 2),
        ];

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_evidence_bounding() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        config.max_evidence_ids_per_alert = 4;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let events: Vec<NetworkEvent> = (1..=10)
            .map(|port| make_test_event(Some(ip), Some(port), port as i64))
            .collect();

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.observation_count, 10);
        assert_eq!(alert.evidence_event_ids.len(), 4);
    }

    #[test]
    fn test_severity_tiers() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 5;
        let rule = PortScanRule::new(config).expect("rule creation");

        assert_eq!(rule.calculate_severity(5), AlertSeverity::Medium);
        assert_eq!(rule.calculate_severity(9), AlertSeverity::Medium);
        assert_eq!(rule.calculate_severity(10), AlertSeverity::High);
        assert_eq!(rule.calculate_severity(19), AlertSeverity::High);
        assert_eq!(rule.calculate_severity(20), AlertSeverity::Critical);
    }
}
