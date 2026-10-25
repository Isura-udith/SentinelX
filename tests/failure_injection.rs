//! Failure injection, boundary validation, and security integration tests
//! for SentinelX defensive monitoring subsystem.

use chrono::{Duration as ChronoDuration, Utc};
use sentinel_app::commands::*;
use sentinel_app::pipeline::{PipelineConfig, PipelineCoordinator};
use sentinel_app::state::{AppSettings, AppState};
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_core::alert::{AlertId, AlertSeverity, AlertStatus, RuleId};
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{ConnectionBurstConfig, ConnectionBurstRule, PortScanRule};
use sentinel_storage::alerts::PersistedAlert;
use sentinel_storage::{
    AuditEntry, Database, DatabaseConfig, MAX_AUDIT_ACTION_LEN, MAX_AUDIT_ACTOR_LEN,
    MAX_AUDIT_DETAILS_BYTES, MAX_AUDIT_TARGET_ID_LEN, MAX_AUDIT_TARGET_TYPE_LEN,
};
use std::path::PathBuf;
use std::sync::Arc;

async fn setup_test_app_state() -> Arc<AppState> {
    let tmp_dir = tempfile::tempdir().expect("temp dir").keep();
    let db_path = tmp_dir.join("test_failure_sentinelx.db");
    let db_config = DatabaseConfig::new(&db_path);
    let database = Database::new(&db_config).await.expect("database init");

    let mut net001 = DetectionConfig::default();
    net001.distinct_port_threshold = 4;
    let net002 = ConnectionBurstConfig::new(
        10,
        ChronoDuration::seconds(60),
        Some(ChronoDuration::seconds(300)),
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

    let state = AppState::new(database, coordinator, settings)
        .await
        .expect("app state init");

    // Stop autonomous background telemetry to isolate tests
    let _ = stop_telemetry_impl(&state).await;
    state
}

#[tokio::test]
async fn test_database_config_validation_rejections() {
    // 1. Empty path rejection
    let empty_cfg = DatabaseConfig::new(PathBuf::new());
    let err_empty = empty_cfg
        .validate()
        .expect_err("empty database path must fail");
    assert!(err_empty.to_string().contains("cannot be empty"));

    // 2. Null byte in path rejection (path traversal / poison injection)
    let null_byte_cfg = DatabaseConfig::new(PathBuf::from("data/sentinel\0x.db"));
    let err_null = null_byte_cfg
        .validate()
        .expect_err("null byte in path must fail");
    assert!(err_null.to_string().contains("null byte"));

    // 3. Zero connection pool size rejection
    let zero_pool_cfg =
        DatabaseConfig::new(PathBuf::from("data/sentinelx.db")).with_max_connections(0);
    let err_pool = zero_pool_cfg
        .validate()
        .expect_err("zero connection pool must fail");
    assert!(err_pool.to_string().contains("greater than zero"));
}

#[tokio::test]
async fn test_audit_entry_boundary_validations() {
    // 1. Oversized actor rejected
    let long_actor = "a".repeat(MAX_AUDIT_ACTOR_LEN + 1);
    let mut entry = AuditEntry::new(
        long_actor,
        "test_action",
        "system",
        None,
        serde_json::json!({}),
    );
    let err_actor = entry.validate().expect_err("oversized actor must fail");
    assert!(err_actor.to_string().contains("actor"));

    // 2. Empty action rejected
    entry.actor = "analyst".to_string();
    entry.action = "   ".to_string();
    let err_action = entry.validate().expect_err("empty action must fail");
    assert!(err_action.to_string().contains("action"));

    // 3. Oversized action rejected
    entry.action = "a".repeat(MAX_AUDIT_ACTION_LEN + 1);
    let err_action_len = entry.validate().expect_err("oversized action must fail");
    assert!(err_action_len.to_string().contains("action"));

    // 4. Oversized target_type rejected
    entry.action = "valid_action".to_string();
    entry.target_type = "t".repeat(MAX_AUDIT_TARGET_TYPE_LEN + 1);
    let err_target_type = entry
        .validate()
        .expect_err("oversized target_type must fail");
    assert!(err_target_type.to_string().contains("target_type"));

    // 5. Oversized target_id rejected
    entry.target_type = "alert".to_string();
    entry.target_id = Some("i".repeat(MAX_AUDIT_TARGET_ID_LEN + 1));
    let err_target_id = entry.validate().expect_err("oversized target_id must fail");
    assert!(err_target_id.to_string().contains("target_id"));

    // 6. Oversized details payload rejected (> 64 KB)
    entry.target_id = Some("alert-123".to_string());
    let huge_str = "x".repeat(MAX_AUDIT_DETAILS_BYTES + 10);
    entry.details_json = serde_json::json!({ "payload": huge_str });
    let err_details = entry.validate().expect_err("huge details must fail");
    assert!(err_details.to_string().contains("exceeds maximum allowed"));

    // 7. Excessive future timestamp skew rejected (> 5 minutes)
    entry.details_json = serde_json::json!({ "ok": true });
    entry.timestamp = Utc::now() + ChronoDuration::minutes(10);
    let err_future = entry
        .validate()
        .expect_err("excessive future skew must fail");
    assert!(err_future.to_string().contains("future clock skew"));

    // 8. Normal entry passes validation
    entry.timestamp = Utc::now();
    assert!(entry.validate().is_ok());
}

#[tokio::test]
async fn test_frontend_command_validation_rejections() {
    let state = setup_test_app_state().await;

    // 1. Oversized search text (> 256 chars) in events query
    let oversized_search = EventQueryParams {
        search_text: Some("s".repeat(257)),
        ..Default::default()
    };
    let err_search = query_network_events_impl(&state, oversized_search)
        .await
        .expect_err("oversized search must fail");
    assert!(err_search.to_string().contains("256 characters"));

    // 2. Oversized IP string (> 64 chars)
    let oversized_ip = EventQueryParams {
        source_ip: Some("1".repeat(65)),
        ..Default::default()
    };
    let err_ip = query_network_events_impl(&state, oversized_ip)
        .await
        .expect_err("oversized IP string must fail");
    assert!(err_ip.to_string().contains("64 characters"));

    // 3. Offset exceeding 1,000,000
    let huge_offset = EventQueryParams {
        offset: Some(1_000_001),
        ..Default::default()
    };
    let err_offset = query_network_events_impl(&state, huge_offset)
        .await
        .expect_err("huge offset must fail");
    assert!(err_offset.to_string().contains("1,000,000"));

    // 4. Oversized analyst note (> 1024 chars)
    let aid = AlertId::new();
    let oversized_note = Some("n".repeat(1025));
    let err_note = acknowledge_alert_impl(&state, aid.to_string(), oversized_note)
        .await
        .expect_err("oversized note must fail");
    assert!(err_note.to_string().contains("1024 characters"));

    // 5. Unsupported detection rule ID
    let invalid_rule = UpdateDetectionRuleInput {
        rule_id: "NET-999".to_string(),
        enabled: true,
        threshold: 10,
        window_duration_secs: 60,
        cooldown_secs: Some(300),
        max_evidence_ids: 20,
    };
    let err_rule = update_detection_rule_impl(&state, invalid_rule)
        .await
        .expect_err("unsupported rule ID must fail");
    assert!(err_rule.to_string().contains("Unsupported rule ID"));

    // 6. Invalid theme allowlist
    let invalid_theme = UpdateApplicationSettingsInput {
        theme: Some("cyberpunk_neon".to_string()),
        refresh_interval_secs: None,
        event_table_page_size: None,
        event_retention_days: None,
        audit_retention_days: None,
        telemetry_polling_interval_ms: None,
        log_verbosity: None,
        is_demo_mode: None,
    };
    let err_theme = update_application_settings_impl(&state, invalid_theme)
        .await
        .expect_err("invalid theme must fail");
    assert!(err_theme.to_string().contains("Theme must be one of"));

    // 7. Invalid log verbosity allowlist
    let invalid_verbosity = UpdateApplicationSettingsInput {
        theme: None,
        refresh_interval_secs: None,
        event_table_page_size: None,
        event_retention_days: None,
        audit_retention_days: None,
        telemetry_polling_interval_ms: None,
        log_verbosity: Some("verbose_everything".to_string()),
        is_demo_mode: None,
    };
    let err_verb = update_application_settings_impl(&state, invalid_verbosity)
        .await
        .expect_err("invalid verbosity must fail");
    assert!(
        err_verb
            .to_string()
            .contains("Log verbosity must be one of")
    );
}

#[tokio::test]
async fn test_collector_failure_injection_handling() {
    let state = setup_test_app_state().await;

    // Inject simulated collector failure (e.g., ACCESS_DENIED from Windows API)
    {
        let mut mock = MockCollector::new();
        mock.inject_failure("ACCESS_DENIED_ERROR");
        let mut coord = state.coordinator.lock().await;
        coord.set_collector(Box::new(mock));
    }

    let cycle_result = {
        let mut coord = state.coordinator.lock().await;
        coord.process_cycle().await
    };

    // Cycle must report error without panic or crash
    assert!(cycle_result.is_err());
    let err_str = cycle_result.unwrap_err().to_string();
    assert!(err_str.contains("ACCESS_DENIED_ERROR"));

    // Collection stats must record failure accurately
    let coord = state.coordinator.lock().await;
    let collection_stats = coord.collection_stats();
    assert_eq!(collection_stats.failed_cycles, 1);
    assert_eq!(collection_stats.raw_records_observed, 0);
}

#[tokio::test]
async fn test_empty_telemetry_snapshot_handling() {
    let state = setup_test_app_state().await;

    // Setup empty snapshot collector
    {
        let mut coord = state.coordinator.lock().await;
        coord.set_collector(Box::new(MockCollector::for_scenario(&MockScenario::Empty)));
    }

    let cycle_result = {
        let mut coord = state.coordinator.lock().await;
        coord.process_cycle().await
    };

    assert!(cycle_result.is_ok());
    let alerts = cycle_result.unwrap();
    assert!(alerts.is_empty());
}

#[tokio::test]
async fn test_invalid_alert_status_transitions_rejected() {
    let state = setup_test_app_state().await;

    let now = Utc::now();
    let new_alert = PersistedAlert {
        id: AlertId::new(),
        rule_id: RuleId::new("NET-001").unwrap(),
        rule_version: "1.0.0".to_string(),
        severity: AlertSeverity::High,
        title: "Test Alert".to_string(),
        description: "Test description".to_string(),
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

    // 1. Resolve alert directly
    resolve_alert_impl(&state, aid.to_string(), Some("Resolved note".to_string()))
        .await
        .expect("resolve succeeds");

    // 2. Attempting to acknowledge a resolved alert must fail
    let err_ack = acknowledge_alert_impl(&state, aid.to_string(), None)
        .await
        .expect_err("acknowledging resolved alert must be rejected");
    assert!(err_ack.to_string().contains("Invalid status transition"));

    // 3. Attempting to resolve an already-resolved alert must also fail
    let err_res = resolve_alert_impl(&state, aid.to_string(), None)
        .await
        .expect_err("resolving resolved alert must be rejected");
    assert!(err_res.to_string().contains("Invalid status transition"));
}
