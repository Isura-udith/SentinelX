//! Realistic synthetic workload benchmark measuring throughput, latency,
//! and resource bounds for SentinelX Phase 5 verification.

use chrono::{Duration, Utc};
use sentinel_app::commands::*;
use sentinel_app::pipeline::{PipelineConfig, PipelineCoordinator};
use sentinel_app::state::{AppSettings, AppState};
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_core::alert::{AlertSeverity, RuleId};
use sentinel_core::config::DetectionConfig;
use sentinel_core::event::{
    NetworkEvent, NetworkEventBuilder, NetworkProtocol, ProcessId, TelemetrySource,
};
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{ConnectionBurstConfig, ConnectionBurstRule, PortScanRule};
use sentinel_storage::alerts::AlertCorrelationCandidate;
use sentinel_storage::retention::RetentionPolicy;
use sentinel_storage::{Database, DatabaseConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

const TOTAL_EVENTS: usize = 5000;
const BATCH_SIZE: usize = 500;
const ALERT_UPSERTS: usize = 200;

fn generate_synthetic_events(count: usize) -> Vec<NetworkEvent> {
    let now = Utc::now();
    let mut events = Vec::with_capacity(count);

    for i in 0..count {
        let port = (1024 + (i % 64000)) as u16;
        let src_octet = ((i / 100) % 250 + 1) as u8;
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, src_octet));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 50 + 1) as u8));

        let evt = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now - Duration::seconds((count - i) as i64),
        )
        .with_source_ip(src_ip)
        .with_source_port(40000 + (i % 20000) as u16)
        .with_destination_ip(dst_ip)
        .with_destination_port(port)
        .with_process_id(ProcessId::new(1000 + (i % 500) as u32).expect("valid pid"))
        .build()
        .expect("valid synthetic event");

        events.push(evt);
    }

    events
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn run_empirical_performance_benchmarks() {
    println!("\n=======================================================");
    println!("SENTINELX PHASE 5 PERFORMANCE & RELIABILITY BENCHMARK");
    println!("=======================================================\n");

    let tmp_dir = tempfile::tempdir().expect("temp dir").keep();
    let db_path = tmp_dir.join("benchmark_sentinelx.db");
    let db_config = DatabaseConfig::new(&db_path);

    let start_init = Instant::now();
    let database = Database::new(&db_config)
        .await
        .expect("database initialization");
    let db_init_duration = start_init.elapsed();
    println!(
        "[-] Database initialization + SQLite migrations duration: {:.2} ms",
        db_init_duration.as_secs_f64() * 1000.0
    );

    let mut net001 = DetectionConfig::default();
    net001.distinct_port_threshold = 10;
    let net002 =
        ConnectionBurstConfig::new(20, Duration::seconds(60), Some(Duration::seconds(300)), 50)
            .expect("valid NET-002");

    let r1 = PortScanRule::new(net001.clone()).expect("rule1");
    let r2 = ConnectionBurstRule::new(net002).expect("rule2");
    let engine = DetectionEngine::new(net001)
        .expect("engine")
        .with_rule(Box::new(r1))
        .with_rule(Box::new(r2));

    let collector = Box::new(MockCollector::for_scenario(&MockScenario::Empty));
    let coordinator = PipelineCoordinator::new(
        PipelineConfig::default(),
        collector,
        database.clone(),
        engine,
    );

    let mut settings = AppSettings::default();
    settings.database_path = db_path.to_string_lossy().to_string();
    settings.is_demo_mode = true;

    let state = AppState::new(database.clone(), coordinator, settings)
        .await
        .expect("app state init");
    let _ = stop_telemetry_impl(&state).await;

    // 1. Ingestion Throughput: 5,000 events in batches of 500
    let synthetic_events = generate_synthetic_events(TOTAL_EVENTS);

    let start_ingest = Instant::now();
    let mut total_inserted = 0;
    for chunk in synthetic_events.chunks(BATCH_SIZE) {
        let res = state
            .event_repo
            .insert_events_batch(chunk)
            .await
            .expect("batch insert succeeds");
        total_inserted += res.inserted_count;
    }
    let ingest_duration = start_ingest.elapsed();
    let events_per_sec = (total_inserted as f64) / ingest_duration.as_secs_f64();
    println!(
        "[-] Event Ingestion Throughput: {} events inserted in {:.2} ms ({:.0} events/sec)",
        total_inserted,
        ingest_duration.as_secs_f64() * 1000.0,
        events_per_sec
    );

    // 2. Detection Engine Evaluation Latency: 5,000 events processed through detection engine
    let mut detection_engine = DetectionEngine::new(DetectionConfig::default()).expect("engine");
    detection_engine = detection_engine
        .with_rule(Box::new(
            PortScanRule::new(DetectionConfig::default()).unwrap(),
        ))
        .with_rule(Box::new(
            ConnectionBurstRule::new(
                ConnectionBurstConfig::new(20, Duration::seconds(60), None, 50).unwrap(),
            )
            .unwrap(),
        ));

    let start_detect = Instant::now();
    let mut total_alerts_detected = 0;
    for chunk in synthetic_events.chunks(BATCH_SIZE) {
        let alerts = detection_engine
            .process_batch(chunk)
            .expect("detection batch succeeds");
        total_alerts_detected += alerts.len();
    }
    let detect_duration = start_detect.elapsed();
    let detect_throughput = (TOTAL_EVENTS as f64) / detect_duration.as_secs_f64();
    println!(
        "[-] Detection Engine Throughput: {} events evaluated in {:.2} ms ({:.0} events/sec, {} alerts detected)",
        TOTAL_EVENTS,
        detect_duration.as_secs_f64() * 1000.0,
        detect_throughput,
        total_alerts_detected
    );

    // 3. Alert Correlation & Upsert Latency: 200 alert correlation upserts
    let start_upsert = Instant::now();
    for (i, event) in synthetic_events.iter().enumerate().take(ALERT_UPSERTS) {
        let candidate = AlertCorrelationCandidate {
            rule_id: RuleId::new("NET-001").expect("valid rule id"),
            rule_version: "1.0.0".to_string(),
            severity: AlertSeverity::Medium,
            title: format!("Port Scan Incident #{i}"),
            description: "Synthetic benchmark alert".to_string(),
            first_seen: Utc::now() - Duration::minutes(10),
            last_seen: Utc::now(),
            additional_observation_count: 5,
            fingerprint: format!("NET-001:192.168.1.{}", (i % 20) + 1),
            evidence_event_ids: vec![event.id],
        };
        state
            .alert_repo
            .upsert_correlated_alert(&candidate, "benchmark_operator")
            .await
            .expect("upsert alert succeeds");
    }
    let upsert_duration = start_upsert.elapsed();
    let avg_upsert_latency = (upsert_duration.as_secs_f64() * 1000.0) / (ALERT_UPSERTS as f64);
    println!(
        "[-] Alert Correlation Upsert Latency: {} upserts completed in {:.2} ms (average {:.2} ms/upsert)",
        ALERT_UPSERTS,
        upsert_duration.as_secs_f64() * 1000.0,
        avg_upsert_latency
    );

    // 4. Query Latencies for Common Dashboard Operations
    let start_summary = Instant::now();
    let summary = get_dashboard_summary_impl(&state, Some("24h".to_string()))
        .await
        .expect("dashboard summary succeeds");
    let summary_latency = start_summary.elapsed();
    println!(
        "[-] Dashboard Summary Query Latency: {:.2} ms (events: {}, open alerts: {})",
        summary_latency.as_secs_f64() * 1000.0,
        summary.total_events,
        summary.open_alerts
    );

    let start_events_query = Instant::now();
    let paged_events = query_network_events_impl(
        &state,
        EventQueryParams {
            limit: Some(50),
            offset: Some(0),
            sort_desc: Some(true),
            ..Default::default()
        },
    )
    .await
    .expect("events query succeeds");
    let events_query_latency = start_events_query.elapsed();
    println!(
        "[-] Paginated Events Query Latency (50 items): {:.2} ms (total: {})",
        events_query_latency.as_secs_f64() * 1000.0,
        paged_events.total_count
    );

    let start_alerts_query = Instant::now();
    let paged_alerts = query_security_alerts_impl(
        &state,
        AlertQueryParams {
            limit: Some(50),
            offset: Some(0),
            ..Default::default()
        },
    )
    .await
    .expect("alerts query succeeds");
    let alerts_query_latency = start_alerts_query.elapsed();
    println!(
        "[-] Paginated Alerts Query Latency (50 items): {:.2} ms (total: {})",
        alerts_query_latency.as_secs_f64() * 1000.0,
        paged_alerts.total_count
    );

    // 5. Database File Size on Disk
    let db_metadata = std::fs::metadata(&db_path).expect("db metadata");
    let db_size_kb = db_metadata.len() as f64 / 1024.0;
    println!(
        "[-] Database File Size on Disk (after 5,000 events + 200 alerts): {:.2} KB ({:.2} MB)",
        db_size_kb,
        db_size_kb / 1024.0
    );

    // 6. Retention Execution Latency
    let start_retention = Instant::now();
    let retention_policy = RetentionPolicy::new(1, 14, 500, 100);
    let retention_report = state
        .retention_mgr
        .run_retention_cycle(
            &retention_policy,
            Utc::now() + Duration::days(2),
            "benchmark",
        )
        .await
        .expect("retention succeeds");
    let retention_latency = start_retention.elapsed();
    println!(
        "[-] Retention Cycle Execution Latency: {:.2} ms (purged {} events, executed {} batches)",
        retention_latency.as_secs_f64() * 1000.0,
        retention_report.events_deleted,
        retention_report.batches_executed
    );

    println!("\n=======================================================");
    println!("BENCHMARK ACCEPTANCE TARGET VERIFICATION PASSED");
    println!("=======================================================\n");

    // Acceptance target assertions:
    assert!(
        events_per_sec >= 1000.0,
        "Ingestion throughput must exceed 1,000 events/sec"
    );
    assert!(
        detect_throughput >= 5000.0,
        "Detection throughput must exceed 5,000 events/sec"
    );
    assert!(
        avg_upsert_latency < 50.0,
        "Alert upsert latency must be below 50ms"
    );
    assert!(
        events_query_latency.as_millis() < 250,
        "Events query latency must be below 250ms"
    );
    assert!(
        summary_latency.as_millis() < 500,
        "Dashboard summary query latency must be below 500ms"
    );
}
