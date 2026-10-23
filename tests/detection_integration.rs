//! End-to-end integration tests for SentinelX detection engine and domain workflow.
//!
//! Verifies the complete analytical pipeline:
//! Synthetic Events -> Domain Validation -> Detection Engine -> Structured Security Alerts.

use chrono::{Duration, Utc};
use sentinel_core::alert::{AlertSeverity, AlertStatus};
use sentinel_core::config::DetectionConfig;
use sentinel_core::event::{NetworkEvent, NetworkEventBuilder, NetworkProtocol, TelemetrySource};
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{PortScanRule, RULE_ID_NET_001};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_end_to_end_detection_pipeline() {
    // 1. Configure detection parameters for test run
    let mut config = DetectionConfig::default();
    config.distinct_port_threshold = 5;
    config.max_evidence_ids_per_alert = 10;

    // 2. Instantiate detection engine and register rule NET-001
    let rule = PortScanRule::new(config.clone()).expect("valid port scan rule");
    let engine = DetectionEngine::new(config)
        .expect("valid engine")
        .with_rule(Box::new(rule));

    let now = Utc::now();

    // 3. Generate synthetic dataset with 4 categories of traffic
    let scanner_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)); // Suspicious scanner: 8 distinct ports
    let web_user_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)); // Benign user: 2 ports (80, 443)
    let poller_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25)); // Benign poller: 12 connections to port 443
    let partial_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)); // Partial telemetry: missing port/IP

    let mut events: Vec<NetworkEvent> = Vec::new();

    // 3a. Scanner: contacts ports 21, 22, 23, 25, 80, 110, 443, 8080 (8 distinct ports >= threshold 5)
    let scanner_ports = [21, 22, 23, 25, 80, 110, 443, 8080];
    for (i, &port) in scanner_ports.iter().enumerate() {
        let ev = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now + Duration::seconds(i as i64),
        )
        .with_source_ip(scanner_ip)
        .with_source_port(40000 + (i as u16))
        .with_destination_port(port)
        .build()
        .expect("scanner event validates");
        events.push(ev);
    }

    // 3b. Benign web user: only ports 80 and 443 (2 distinct ports < threshold 5)
    for (i, &port) in [80, 443].iter().enumerate() {
        let ev = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now + Duration::seconds(10 + i as i64),
        )
        .with_source_ip(web_user_ip)
        .with_source_port(50000 + (i as u16))
        .with_destination_port(port)
        .build()
        .expect("web user event validates");
        events.push(ev);
    }

    // 3c. Benign poller: 12 repeated connections to port 443 (distinct count = 1 < threshold 5)
    for i in 0..12 {
        let ev = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now + Duration::seconds(20 + i as i64),
        )
        .with_source_ip(poller_ip)
        .with_source_port(55000 + (i as u16))
        .with_destination_port(443)
        .build()
        .expect("poller event validates");
        events.push(ev);
    }

    // 3d. Incomplete telemetry: missing port or missing IP
    let partial_event_1 = NetworkEventBuilder::new(
        TelemetrySource::SyntheticSimulator,
        NetworkProtocol::Tcp,
        now + Duration::seconds(40),
    )
    .with_source_ip(partial_ip)
    // destination_port left as None
    .build()
    .expect("partial event 1 validates");
    events.push(partial_event_1);

    let partial_event_2 = NetworkEventBuilder::new(
        TelemetrySource::SyntheticSimulator,
        NetworkProtocol::Tcp,
        now + Duration::seconds(41),
    )
    // source_ip left as None
    .with_destination_port(8080)
    .build()
    .expect("partial event 2 validates");
    events.push(partial_event_2);

    // Total events: 8 + 2 + 12 + 2 = 24
    assert_eq!(events.len(), 24);

    // 4. Execute detection engine against event batch
    let alerts = engine
        .process_batch(&events)
        .expect("batch execution succeeds");

    // 5. Assert alert results
    // Exactly 1 alert must be generated (for the scanner IP)
    assert_eq!(alerts.len(), 1, "Expected exactly 1 alert for the scanner");
    let alert = &alerts[0];

    assert_eq!(alert.rule_id.as_str(), RULE_ID_NET_001);
    assert_eq!(alert.source_ip, Some(scanner_ip));
    assert_eq!(alert.status, AlertStatus::Open);
    assert_eq!(alert.observation_count, 8);
    assert_eq!(alert.evidence_event_ids.len(), 8);
    // Threshold is 5; 8 distinct ports gives Medium (< 5 * 2)
    assert_eq!(alert.severity, AlertSeverity::Medium);

    // 6. Verify explanation and title content
    assert!(alert.title.contains("192.0.2.10"));
    assert!(alert.explanation.contains("8 distinct destination ports"));
    assert!(alert.explanation.contains("detection signal"));

    // 7. Verify JSON serialization and roundtrip
    let alert_json = serde_json::to_string_pretty(&alert).expect("serialization to JSON");
    assert!(alert_json.contains("\"rule_id\": \"NET-001\""));
    assert!(alert_json.contains("\"source_ip\": \"192.0.2.10\""));

    let deserialized_alert: sentinel_core::alert::SecurityAlert =
        serde_json::from_str(&alert_json).expect("deserialization from JSON");
    assert_eq!(alert, &deserialized_alert);
}
