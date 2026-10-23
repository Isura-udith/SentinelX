//! Integration test: Mock Collector -> Normalization -> Detection Engine -> Security Alerts.
//!
//! Verifies the complete Phase 2 mock telemetry collection and detection pipeline.

use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_collector::source::TelemetryCollector;
use sentinel_core::alert::{AlertSeverity, AlertStatus};
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{PortScanRule, RULE_ID_NET_001};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_mock_collector_detection_pipeline() {
    // 1. Configure detection engine with threshold = 5 distinct ports:
    let mut config = DetectionConfig::default();
    config.distinct_port_threshold = 5;
    config.max_evidence_ids_per_alert = 15;

    let rule = PortScanRule::new(config.clone()).expect("valid port scan rule");
    let engine = DetectionEngine::new(config)
        .expect("valid engine")
        .with_rule(Box::new(rule));

    // 2. Initialize MockCollector with Mixed scenario:
    // Mixed scenario contains:
    // - Host 192.0.2.10 sweeping 6 ports (22, 80, 443, 8080, 8443, 9000) -> crosses threshold 5!
    // - Host 198.51.100.25 repeating port 443 eight times -> distinct ports = 1 -> no alert!
    // - Listening socket (0.0.0.0:8080 -> 0.0.0.0:0) -> skipped per policy!
    // - IPv6 localhost connection (::1:55555 -> ::1:443) -> distinct ports = 1 -> no alert!
    let mut collector = MockCollector::for_scenario(&MockScenario::Mixed);

    // 3. Execute collection:
    let batch = collector.collect().expect("mock collection succeeds");

    // 4. Verify batch metadata:
    assert_eq!(batch.metadata.raw_records_observed, 16);
    assert_eq!(batch.metadata.records_skipped, 1);
    assert_eq!(batch.metadata.normalized_events_produced, 15);
    assert_eq!(batch.events.len(), 15);

    // 5. Pass normalized events into detection engine:
    let alerts = engine
        .process_batch(&batch.events)
        .expect("detection evaluation succeeds");

    // 6. Assert detection outcome:
    // Exactly 1 alert generated for the scanner host 192.0.2.10:
    assert_eq!(
        alerts.len(),
        1,
        "Expected exactly 1 alert for the port sweep scanner"
    );

    let alert = &alerts[0];
    assert_eq!(alert.rule_id.as_str(), RULE_ID_NET_001);
    assert_eq!(
        alert.source_ip,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
    assert_eq!(alert.severity, AlertSeverity::Medium); // 6 ports: 5 <= count < 10
    assert_eq!(alert.status, AlertStatus::Open);
    assert_eq!(alert.observation_count, 6);
    assert_eq!(alert.evidence_event_ids.len(), 6);

    // 7. Verify repeated observations do not inflate distinct port count:
    let poller_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25));
    let poller_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.source_ip == Some(poller_ip))
        .collect();
    assert!(
        poller_alerts.is_empty(),
        "Repeated connections to the same port must not trigger port scan alert"
    );
}

#[test]
fn test_mock_empty_snapshot_produces_no_alerts() {
    let mut config = DetectionConfig::default();
    config.distinct_port_threshold = 3;
    let rule = PortScanRule::new(config.clone()).unwrap();
    let engine = DetectionEngine::new(config)
        .unwrap()
        .with_rule(Box::new(rule));

    let mut collector = MockCollector::for_scenario(&MockScenario::Empty);
    let batch = collector.collect().expect("empty collection succeeds");

    assert_eq!(batch.metadata.raw_records_observed, 0);
    assert_eq!(batch.metadata.normalized_events_produced, 0);
    assert_eq!(batch.metadata.records_skipped, 0);

    let alerts = engine
        .process_batch(&batch.events)
        .expect("evaluation succeeds");
    assert!(alerts.is_empty());
}
