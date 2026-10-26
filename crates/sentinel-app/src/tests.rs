//! Integration and unit tests verifying typed commands, state management,
//! and defensive invariants.

use crate::commands::*;
use crate::pipeline::{PipelineConfig, PipelineCoordinator};
use crate::state::{AppSettings, AppState};
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_core::alert::{AlertSeverity, AlertStatus, RuleId};
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{ConnectionBurstConfig, ConnectionBurstRule, PortScanRule};
use sentinel_storage::alerts::PersistedAlert;
use sentinel_storage::{Database, DatabaseConfig};
use std::sync::Arc;

async fn setup_test_app_state() -> Arc<AppState> {
    let tmp_dir = tempfile::tempdir().expect("temp dir").keep();
    let db_path = tmp_dir.join("test_sentinelx.db");
    let db_config = DatabaseConfig::new(&db_path);
    let database = Database::new(&db_config).await.expect("database init");

    let mut net001 = DetectionConfig::default();
    net001.distinct_port_threshold = 4;
    let net002 = ConnectionBurstConfig::new(
        10,
        chrono::Duration::seconds(60),
        Some(chrono::Duration::seconds(300)),
        20,
    )
    .expect("valid NET-002");

    let r1 = PortScanRule::new(net001.clone()).expect("rule1");
    let r2 = ConnectionBurstRule::new(net002).expect("rule2");
    let engine = DetectionEngine::new(net001)
        .expect("engine")
        .with_rule(Box::new(r1))
        .with_rule(Box::new(r2));

    let collector = Box::new(MockCollector::for_scenario(&MockScenario::PortSweep {
        scanner_ip: "192.0.2.100".parse().unwrap(),
        ports: vec![22, 80, 443, 8080, 8443],
    }));

    let coordinator = PipelineCoordinator::new(
        PipelineConfig::default(),
        collector,
        database.clone(),
        engine,
    );

    let mut settings = AppSettings::default();
    settings.database_path = db_path.to_string_lossy().to_string();
    settings.is_demo_mode = true;

    AppState::new(database, coordinator, settings)
        .await
        .expect("app state init")
}

#[tokio::test]
async fn test_system_status_and_dashboard_summary() {
    let state = setup_test_app_state().await;

    let status = get_system_status_impl(&state)
        .await
        .expect("get_system_status success");
    assert!(status.database_connected);
    assert!(status.is_demo_mode);
    assert!(status.telemetry_running);

    let summary = get_dashboard_summary_impl(&state, Some("24h".to_string()))
        .await
        .expect("get_dashboard_summary success");
    assert_eq!(summary.activity_time_series.len(), 12);
}

#[tokio::test]
async fn test_event_query_validation() {
    let state = setup_test_app_state().await;

    // Invalid port 0 must be rejected with validation error
    let invalid_port_query = EventQueryParams {
        destination_port: Some(0),
        ..Default::default()
    };
    let err = query_network_events_impl(&state, invalid_port_query)
        .await
        .expect_err("port 0 must fail");
    assert!(err.to_string().contains("between 1 and 65535"));

    // Inverted time range must be rejected
    let inverted_time_query = EventQueryParams {
        start_time: Some(chrono::Utc::now()),
        end_time: Some(chrono::Utc::now() - chrono::Duration::hours(2)),
        ..Default::default()
    };
    let err_time = query_network_events_impl(&state, inverted_time_query)
        .await
        .expect_err("inverted time range must fail");
    assert!(err_time.to_string().contains("cannot be after"));
}

#[tokio::test]
async fn test_alert_lifecycle_and_invalid_transitions() {
    let state = setup_test_app_state().await;
    let _ = stop_telemetry_impl(&state).await;

    // Create an initial open alert in storage
    let now = chrono::Utc::now();
    let new_alert = PersistedAlert {
        id: sentinel_core::alert::AlertId::new(),
        rule_id: RuleId::new("NET-001").unwrap(),
        rule_version: "1.0.0".to_string(),
        severity: AlertSeverity::High,
        title: "Test Scan Alert".to_string(),
        description: "Reconnaissance activity observed".to_string(),
        first_seen: now,
        last_seen: now,
        created_at: now,
        updated_at: now,
        status: AlertStatus::Open,
        event_count: 5,
        fingerprint: "NET-001:192.0.2.100".to_string(),
        evidence_event_ids: Vec::new(),
    };

    let aid = state
        .alert_repo
        .create_alert(&new_alert, "test_setup")
        .await
        .expect("create alert");

    // 1. Acknowledge alert
    acknowledge_alert_impl(
        &state,
        aid.to_string(),
        Some("Investigating analyst".to_string()),
    )
    .await
    .expect("acknowledge succeeds");

    // Verify status updated in database
    let updated = state
        .alert_repo
        .get_alert_by_id(aid)
        .await
        .unwrap()
        .expect("found alert");
    assert_eq!(updated.status, AlertStatus::Acknowledged);

    // 2. Resolve alert
    resolve_alert_impl(
        &state,
        aid.to_string(),
        Some("Remediated false positive".to_string()),
    )
    .await
    .expect("resolve succeeds");

    let resolved = state
        .alert_repo
        .get_alert_by_id(aid)
        .await
        .unwrap()
        .expect("found alert");
    assert_eq!(resolved.status, AlertStatus::Resolved);

    // 3. Attempt invalid transition (acknowledging a resolved alert must fail)
    let inv_err = acknowledge_alert_impl(&state, aid.to_string(), None)
        .await
        .expect_err("acknowledging resolved alert must be rejected");
    assert!(inv_err.to_string().contains("Invalid status transition"));
}

#[tokio::test]
async fn test_detection_rule_update_and_validation() {
    let state = setup_test_app_state().await;

    let rules = get_detection_rules_impl(&state).await.expect("get rules");
    assert!(rules.iter().any(|r| r.rule_id == "NET-001"));

    // Validation rejection for zero threshold
    let invalid_input = UpdateDetectionRuleInput {
        rule_id: "NET-001".to_string(),
        enabled: true,
        threshold: 0,
        window_duration_secs: 60,
        cooldown_secs: Some(300),
        max_evidence_ids: 20,
    };
    let err = update_detection_rule_impl(&state, invalid_input)
        .await
        .expect_err("zero threshold must fail");
    assert!(err.to_string().contains("greater than zero"));

    // Valid update
    let valid_input = UpdateDetectionRuleInput {
        rule_id: "NET-001".to_string(),
        enabled: true,
        threshold: 15,
        window_duration_secs: 120,
        cooldown_secs: Some(600),
        max_evidence_ids: 30,
    };
    update_detection_rule_impl(&state, valid_input)
        .await
        .expect("valid update succeeds");

    let updated_rules = get_detection_rules_impl(&state).await.unwrap();
    let net001 = updated_rules
        .iter()
        .find(|r| r.rule_id == "NET-001")
        .unwrap();
    assert_eq!(net001.threshold, 15);
    assert_eq!(net001.window_duration_secs, 120);
}

#[tokio::test]
async fn test_telemetry_control_idempotency() {
    let state = setup_test_app_state().await;

    // Stop telemetry
    stop_telemetry_impl(&state).await.expect("stop succeeds");
    let s1 = get_telemetry_status_impl(&state).await.unwrap();
    assert!(!s1.is_running);

    // Stop again (idempotent)
    stop_telemetry_impl(&state)
        .await
        .expect("repeated stop succeeds idempotently");

    // Start telemetry
    start_telemetry_impl(&state).await.expect("start succeeds");
    let s2 = get_telemetry_status_impl(&state).await.unwrap();
    assert!(s2.is_running);

    // Start again (idempotent)
    start_telemetry_impl(&state)
        .await
        .expect("repeated start succeeds idempotently");
}

#[tokio::test]
async fn test_system_diagnostics_live_state() {
    let state = setup_test_app_state().await;

    let diag = get_system_diagnostics_impl(&state)
        .await
        .expect("system diagnostics query succeeds");

    assert!(diag.backend_initialized);
    assert!(diag.database_connected);
    assert_eq!(diag.app_version, "1.0.0");
    assert!(diag.collector_is_running);
    assert_eq!(diag.database_schema_version, "v3");
    assert_eq!(diag.total_persisted_events, 0);
    assert_eq!(diag.total_persisted_alerts, 0);
    assert!(diag.latest_application_error.is_none());
}
