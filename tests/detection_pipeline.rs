//! End-to-end integration test for `SentinelX` telemetry, persistence, stateful detection,
//! and alert correlation pipeline.
//!
//! Verifies the complete flow:
//! Mock Collector
//! -> Normalization
//! -> Bounded Transactional Event Persistence (SQLite)
//! -> Stateful Detection Engine (NET-001 and NET-002)
//! -> Alert Correlation & Fingerprint Deduplication
//! -> Durable Alert & Evidence Persistence
//! -> Reopening Database from Fresh Connection & Integrity Verification

use sentinel_app::pipeline::{PipelineConfig, PipelineCoordinator};
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_core::alert::AlertSeverity;
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{
    ConnectionBurstConfig, ConnectionBurstRule, PortScanRule, RULE_ID_NET_001,
};
use sentinel_storage::alerts::AlertQueryFilter;
use sentinel_storage::{Database, DatabaseConfig};
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_end_to_end_telemetry_persistence_and_detection_pipeline() {
    // 1. Create an isolated temporary database file
    let tmp = NamedTempFile::new().expect("temp database file");
    let db_path = tmp.path().to_path_buf();

    // 2. Configure SQLite storage with migrations applied
    let db_config = DatabaseConfig::new(&db_path);
    let database = Database::new(&db_config)
        .await
        .expect("initialized file-backed database");

    // 3. Configure detection engine with NET-001 and NET-002
    let mut net001_config = DetectionConfig::default();
    net001_config.distinct_port_threshold = 4; // Threshold 4 distinct ports
    net001_config.max_evidence_ids_per_alert = 10;

    let net002_config = ConnectionBurstConfig::new(
        8, // Threshold 8 observations
        chrono::Duration::seconds(60),
        None,
        15,
    )
    .expect("valid NET-002 config");

    let rule_port_scan = PortScanRule::new(net001_config.clone()).expect("valid port scan rule");
    let rule_conn_burst =
        ConnectionBurstRule::new(net002_config).expect("valid connection burst rule");

    let engine = DetectionEngine::new(net001_config)
        .expect("valid detection engine")
        .with_rule(Box::new(rule_port_scan))
        .with_rule(Box::new(rule_conn_burst));

    // 4. Use deterministic mock collector with PortSweep scenario
    let sweep_scenario = MockScenario::PortSweep {
        scanner_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 88)),
        ports: vec![21, 22, 23, 25, 80, 443, 8080],
    };
    let collector = Box::new(MockCollector::for_scenario(&sweep_scenario));
    let pipeline_config = PipelineConfig {
        version: "0.3.0-test".to_string(),
        operator_actor: "integration_test".to_string(),
    };

    let mut coordinator = PipelineCoordinator::new(pipeline_config, collector, database, engine);

    // 5. Execute Cycle 1: initial telemetry snapshot
    let cycle1_alerts = coordinator
        .process_cycle()
        .await
        .expect("cycle 1 execution");

    assert!(
        !cycle1_alerts.is_empty(),
        "PortSweep scenario must produce alerts"
    );

    // Verify events were persisted to SQLite
    let stored_events_c1 = coordinator.event_repo().count_events().await.unwrap();
    assert!(
        stored_events_c1 > 0,
        "events must be persisted in events table"
    );

    // Verify alert was persisted in SQLite
    let stored_alerts_c1 = coordinator.alert_repo().count_alerts().await.unwrap();
    assert!(
        stored_alerts_c1 > 0,
        "alerts must be persisted in alerts table"
    );

    // Check pipeline metrics
    let metrics = coordinator.metrics();
    assert!(
        metrics
            .events_ingested
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    assert!(
        metrics
            .alerts_created
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );

    // 6. Execute Cycle 2: repeated telemetry (snapshot repetition / subsequent observations)
    let _cycle2_alerts = coordinator
        .process_cycle()
        .await
        .expect("cycle 2 execution");

    // Cycle 2 should correlate into existing active alert or ignore duplicate events
    let stored_events_c2 = coordinator.event_repo().count_events().await.unwrap();
    assert!(stored_events_c2 >= stored_events_c1);

    // 7. Verify persisted alerts from a fresh database connection
    {
        let db_verify = Database::new(&db_config)
            .await
            .expect("reopened database connection");
        let alert_repo_verify = sentinel_storage::AlertRepository::new(db_verify.pool().clone());
        let event_repo_verify = sentinel_storage::EventRepository::new(db_verify.pool().clone());

        let all_alerts = alert_repo_verify
            .query_alerts(&AlertQueryFilter::new().with_limit(10))
            .await
            .expect("query alerts from fresh connection");

        assert!(!all_alerts.is_empty());
        let port_scan_alert = all_alerts
            .iter()
            .find(|a| a.rule_id.as_str() == RULE_ID_NET_001)
            .expect("NET-001 alert must be present");

        assert_eq!(port_scan_alert.severity, AlertSeverity::Medium);
        assert!(!port_scan_alert.evidence_event_ids.is_empty());

        // Verify that every linked evidence event exists in SQLite events table!
        for &evidence_id in &port_scan_alert.evidence_event_ids {
            let event_record = event_repo_verify
                .get_event_by_id(evidence_id)
                .await
                .expect("query evidence event")
                .expect("evidence event record must exist in SQLite");
            assert_eq!(event_record.event.id, evidence_id);
        }

        db_verify.close().await;
    }
}
