//! Detection Rule `NET-001`: Port-Scan-Like Activity Detection.
//!
//! # Objective
//! Identifies a single source IP address that attempts or establishes connections to an
//! unusual number of distinct destination ports within a single observation batch.
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
//! **Important**:
//! An alert emitted by this rule constitutes a **detection signal for triage**, not definitive
//! proof of hostile compromise. SentinelX strictly refrains from automated containment
//! (such as firewall blocks or host isolation) to prevent inadvertent denial of service
//! against legitimate administrative operations.
//!
//! # Telemetry Handling Policy
//! - Observations missing `source_ip` or `destination_port` cannot be attributed to a remote
//!   scanner and are safely ignored by this rule without generating errors or false alerts.
//! - Duplicate connection observations targeting the same destination port are aggregated
//!   under `observation_count` but **never** increase the distinct destination port count.
//! - Observations from different source IPs are strictly isolated and never aggregated.

use crate::engine::{DetectionError, DetectionRule};
use chrono::{DateTime, Utc};
use sentinel_core::alert::{AlertId, AlertSeverity, AlertStatus, RuleId, SecurityAlert};
use sentinel_core::config::DetectionConfig;
use sentinel_core::event::{EventId, NetworkEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Rule identifier constant for `NET-001`.
pub const RULE_ID_NET_001: &str = "NET-001";
/// Human-readable name for `NET-001`.
pub const RULE_NAME_NET_001: &str = "Port-Scan-Like Activity Detection";

/// Implementation of Rule `NET-001`.
#[derive(Debug, Clone)]
pub struct PortScanRule {
    rule_id: RuleId,
    config: DetectionConfig,
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
        Ok(Self { rule_id, config })
    }

    /// Determines the appropriate [`AlertSeverity`] based on distinct port count using checked arithmetic.
    fn calculate_severity(&self, distinct_port_count: usize) -> AlertSeverity {
        let base_threshold = self.config.distinct_port_threshold as usize;

        // Use checked saturating arithmetic to avoid overflow vulnerabilities.
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

/// Internal accumulator for tracking connection observations from a single source IP.
#[derive(Debug)]
struct SourceObservationState {
    distinct_ports: BTreeSet<u16>,
    evidence_ids: Vec<EventId>,
    observation_count: usize,
    first_observed: DateTime<Utc>,
    last_observed: DateTime<Utc>,
}

impl DetectionRule for PortScanRule {
    fn id(&self) -> &RuleId {
        &self.rule_id
    }

    fn name(&self) -> &str {
        RULE_NAME_NET_001
    }

    fn description(&self) -> &'static str {
        "Detects a single source IP contacting an unusual count of distinct destination ports in an observation batch."
    }

    fn evaluate(&self, events: &[NetworkEvent]) -> Result<Vec<SecurityAlert>, DetectionError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        // BTreeMap ensures deterministic ordering of source IP processing.
        let mut tracker: BTreeMap<IpAddr, SourceObservationState> = BTreeMap::new();

        for event in events {
            // Documented policy: events missing source_ip or destination_port are skipped.
            let (Some(source_ip), Some(dest_port)) = (event.source_ip, event.destination_port)
            else {
                continue;
            };

            tracker
                .entry(source_ip)
                .and_modify(|state| {
                    state.distinct_ports.insert(dest_port);
                    state.observation_count = state.observation_count.saturating_add(1);
                    if state.evidence_ids.len() < self.config.max_evidence_ids_per_alert {
                        state.evidence_ids.push(event.id);
                    }
                    if event.timestamp < state.first_observed {
                        state.first_observed = event.timestamp;
                    }
                    if event.timestamp > state.last_observed {
                        state.last_observed = event.timestamp;
                    }
                })
                .or_insert_with(|| {
                    let mut ports = BTreeSet::new();
                    ports.insert(dest_port);
                    let mut evidence =
                        Vec::with_capacity(self.config.max_evidence_ids_per_alert.min(8));
                    evidence.push(event.id);
                    SourceObservationState {
                        distinct_ports: ports,
                        evidence_ids: evidence,
                        observation_count: 1,
                        first_observed: event.timestamp,
                        last_observed: event.timestamp,
                    }
                });
        }

        let mut alerts = Vec::new();
        let threshold = self.config.distinct_port_threshold as usize;

        for (source_ip, state) in tracker {
            let distinct_count = state.distinct_ports.len();
            if distinct_count >= threshold {
                let severity = self.calculate_severity(distinct_count);
                let title = format!(
                    "Port-Scan-Like Activity from {source_ip} ({distinct_count} distinct destination ports)"
                );

                // Sample up to 8 ports for human-readable diagnostic context in the explanation.
                let sampled_ports: Vec<String> = state
                    .distinct_ports
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

                let explanation = format!(
                    "Source IP {source_ip} was observed contacting {distinct_count} distinct destination ports \
                    (threshold: {threshold}) across {obs_count} total connection observations. Sampled target ports: \
                    [{port_sample_str}{more_indicator}]. \
                    Note: This alert constitutes a detection signal for analyst review. Legitimate network scanners, \
                    diagnostic tools, or multi-port service communications can cause similar telemetry patterns.",
                    obs_count = state.observation_count
                );

                let alert = SecurityAlert {
                    id: AlertId::new(),
                    rule_id: self.rule_id.clone(),
                    severity,
                    title,
                    explanation,
                    first_observed_at: state.first_observed,
                    last_observed_at: state.last_observed,
                    observation_count: state.observation_count,
                    source_ip: Some(source_ip),
                    evidence_event_ids: state.evidence_ids,
                    status: AlertStatus::Open,
                };

                // Validate before emitting to guarantee invariant integrity.
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
    use chrono::Duration;
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
        // 10 connection observations, but all targeting port 443!
        let events: Vec<NetworkEvent> = (0..10)
            .map(|i| make_test_event(Some(ip), Some(443), i))
            .collect();

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        // Distinct port count is 1 < threshold 3; must NOT alert!
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_multiple_source_addresses_isolated() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 32));

        // IP A accesses 2 ports (below threshold 3)
        // IP B accesses 2 ports (below threshold 3)
        let events = vec![
            make_test_event(Some(ip_a), Some(80), 0),
            make_test_event(Some(ip_a), Some(443), 1),
            make_test_event(Some(ip_b), Some(22), 2),
            make_test_event(Some(ip_b), Some(25), 3),
        ];

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        // Neither IP crossed the threshold; must NOT alert!
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
            make_test_event(None, Some(80), 0),     // missing source_ip
            make_test_event(Some(ip), None, 1),     // missing dest_port
            make_test_event(Some(ip), Some(80), 2), // valid (port 80)
        ];

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        // Only 1 valid distinct port for IP 40; threshold is 2 -> no alert
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_evidence_bounding() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        config.max_evidence_ids_per_alert = 4;
        let rule = PortScanRule::new(config).expect("rule creation");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        // 10 distinct port connections
        let events: Vec<NetworkEvent> = (1..=10)
            .map(|port| make_test_event(Some(ip), Some(port), port as i64))
            .collect();

        let alerts = rule.evaluate(&events).expect("evaluation succeeds");
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.observation_count, 10);
        // Evidence IDs must be bounded to max_evidence_ids_per_alert (4)
        assert_eq!(alert.evidence_event_ids.len(), 4);
    }

    #[test]
    fn test_severity_tiers() {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 5;
        let rule = PortScanRule::new(config).expect("rule creation");

        // 5 ports -> Medium
        assert_eq!(rule.calculate_severity(5), AlertSeverity::Medium);
        // 9 ports -> Medium (< 10)
        assert_eq!(rule.calculate_severity(9), AlertSeverity::Medium);
        // 10 ports -> High (>= 5 * 2)
        assert_eq!(rule.calculate_severity(10), AlertSeverity::High);
        // 19 ports -> High (< 20)
        assert_eq!(rule.calculate_severity(19), AlertSeverity::High);
        // 20 ports -> Critical (>= 5 * 4)
        assert_eq!(rule.calculate_severity(20), AlertSeverity::Critical);
    }
}
