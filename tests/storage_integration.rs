//! Comprehensive database integration tests for SentinelX storage subsystem.
//!
//! Tests:
//! - Database initialization and migration execution
//! - Foreign-key constraint enforcement
//! - Single event insertion and idempotent duplicate insertion
//! - Transactional batch event insertion and rollback on failure
//! - Pagination, time filtering, and counting
//! - Alert creation, evidence linking, and retrieval
//! - Alert correlation (active alert updating vs new alert creation)
//! - Concurrency and status lifecycle transitions (Open -> Ack -> Resolved)
//! - Invalid status transition rejection
//! - Database reopening across independent pool connections
//! - Retention cleanup with forensic evidence preservation
//! - Audit log records and querying

use chrono::{Duration, Utc};
use sentinel_core::alert::{AlertId, AlertSeverity, AlertStatus, RuleId};
use sentinel_core::event::{
    EventId, NetworkEvent, NetworkEventBuilder, NetworkProtocol, TelemetrySource,
};
use sentinel_storage::alerts::{AlertCorrelationCandidate, CorrelationOutcome, PersistedAlert};
use sentinel_storage::audit::AuditQueryFilter;
use sentinel_storage::events::EventQueryFilter;
use sentinel_storage::retention::RetentionPolicy;
use sentinel_storage::{
    AlertRepository, AuditLogRepository, Database, DatabaseConfig, EventRepository,
    RetentionManager, StorageError,
};
use std::net::{IpAddr, Ipv4Addr};
use tempfile::NamedTempFile;

fn sample_event(source_ip: IpAddr, port: u16, timestamp: chrono::DateTime<Utc>) -> NetworkEvent {
    NetworkEventBuilder::new(
        TelemetrySource::SyntheticSimulator,
        NetworkProtocol::Tcp,
        timestamp,
    )
    .with_source_ip(source_ip)
    .with_source_port(40000)
    .with_destination_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    .with_destination_port(port)
    .build()
    .expect("valid sample event")
}

#[tokio::test]
async fn test_database_initialization_and_migrations() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let event_repo = EventRepository::new(db.pool().clone());
    let alert_repo = AlertRepository::new(db.pool().clone());

    assert_eq!(event_repo.count_events().await.unwrap(), 0);
    assert_eq!(alert_repo.count_alerts().await.unwrap(), 0);
}

#[tokio::test]
async fn test_foreign_key_enforcement() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let pool = db.pool();

    // Directly attempting to insert an alert_events link for a non-existent alert/event
    // must fail due to foreign key enforcement:
    let dummy_alert_id = AlertId::new().to_string();
    let dummy_event_id = EventId::new().to_string();
    let now = Utc::now().to_rfc3339();

    let result =
        sqlx::query("INSERT INTO alert_events (alert_id, event_id, linked_at) VALUES (?, ?, ?)")
            .bind(dummy_alert_id)
            .bind(dummy_event_id)
            .bind(now)
            .execute(pool)
            .await;

    assert!(
        result.is_err(),
        "foreign key constraint must prevent dangling alert_events references"
    );
}

#[tokio::test]
async fn test_single_and_idempotent_event_insertion() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let event_repo = EventRepository::new(db.pool().clone());

    let now = Utc::now();
    let event = sample_event(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80, now);

    // First insert succeeds:
    let inserted = event_repo.insert_event(&event).await.expect("first insert");
    assert!(inserted);
    assert_eq!(event_repo.count_events().await.unwrap(), 1);

    // Duplicate insert of same EventId is an idempotent no-op:
    let re_inserted = event_repo
        .insert_event(&event)
        .await
        .expect("duplicate insert");
    assert!(!re_inserted);
    assert_eq!(event_repo.count_events().await.unwrap(), 1);

    // Verify fetched record:
    let fetched = event_repo
        .get_event_by_id(event.id)
        .await
        .unwrap()
        .expect("found event");
    assert_eq!(fetched.event.id, event.id);
    assert_eq!(fetched.event.destination_port, Some(80));
}

#[tokio::test]
async fn test_batch_insertion_and_transaction_rollback() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let event_repo = EventRepository::new(db.pool().clone());

    let now = Utc::now();
    let mut batch = Vec::new();
    for port in 1..=10 {
        batch.push(sample_event(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port,
            now,
        ));
    }

    let result = event_repo
        .insert_events_batch(&batch)
        .await
        .expect("batch insert");
    assert_eq!(result.inserted_count, 10);
    assert_eq!(result.duplicate_count, 0);
    assert_eq!(event_repo.count_events().await.unwrap(), 10);

    // Re-inserting the same batch reports duplicates and does not inflate count:
    let re_result = event_repo
        .insert_events_batch(&batch)
        .await
        .expect("duplicate batch");
    assert_eq!(re_result.inserted_count, 0);
    assert_eq!(re_result.duplicate_count, 10);
    assert_eq!(event_repo.count_events().await.unwrap(), 10);

    // Now test transaction rollback on malformed event in batch:
    let mut invalid_batch = Vec::new();
    invalid_batch.push(sample_event(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        8080,
        now,
    ));

    // Construct a malformed event with port 0 (violates domain constraint):
    let mut bad_event = sample_event(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8081, now);
    bad_event.destination_port = Some(0);
    invalid_batch.push(bad_event);

    let batch_err = event_repo.insert_events_batch(&invalid_batch).await;
    assert!(batch_err.is_err(), "batch with invalid event must fail");

    // Ensure NONE of the events from the invalid batch were committed:
    assert_eq!(
        event_repo.count_events().await.unwrap(),
        10,
        "rollback must leave database unchanged"
    );
}

#[tokio::test]
async fn test_pagination_and_time_filtering() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let event_repo = EventRepository::new(db.pool().clone());

    let base_time = Utc::now();
    let mut events = Vec::new();

    for i in 0..15 {
        let t = base_time + Duration::seconds(i);
        let port = u16::try_from(8000 + i).unwrap();
        events.push(sample_event(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            port,
            t,
        ));
    }
    event_repo
        .insert_events_batch(&events)
        .await
        .expect("inserted test events");

    // Page 1: limit 5
    let p1_filter = EventQueryFilter::new().with_limit(5).with_offset(0);
    let p1 = event_repo.query_events(&p1_filter).await.unwrap();
    assert_eq!(p1.len(), 5);
    assert_eq!(p1[0].event.destination_port, Some(8000));

    // Page 2: limit 5, offset 5
    let p2_filter = EventQueryFilter::new().with_limit(5).with_offset(5);
    let p2 = event_repo.query_events(&p2_filter).await.unwrap();
    assert_eq!(p2.len(), 5);
    assert_eq!(p2[0].event.destination_port, Some(8005));

    // Time boundary filter: items between index 3 and 7 (5 items)
    let t_start = base_time + Duration::seconds(3);
    let t_end = base_time + Duration::seconds(7);
    let time_filter = EventQueryFilter::new()
        .with_time_range(t_start, t_end)
        .with_limit(100);
    let time_res = event_repo.query_events(&time_filter).await.unwrap();
    assert_eq!(time_res.len(), 5);

    // Combined port and time filter: explicitly tests placeholder bind alignment
    let mixed_filter = EventQueryFilter::new()
        .with_destination_port(8005)
        .with_time_range(t_start, t_end)
        .with_limit(10);
    let mixed_res = event_repo.query_events(&mixed_filter).await.unwrap();
    assert_eq!(mixed_res.len(), 1);
    assert_eq!(mixed_res[0].event.destination_port, Some(8005));
}

#[tokio::test]
async fn test_alert_persistence_evidence_and_lifecycle() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let event_repo = EventRepository::new(db.pool().clone());
    let alert_repo = AlertRepository::new(db.pool().clone());
    let audit_repo = AuditLogRepository::new(db.pool().clone());

    let now = Utc::now();
    let event1 = sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), 22, now);
    let event2 = sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), 80, now);
    event_repo
        .insert_events_batch(&[event1.clone(), event2.clone()])
        .await
        .unwrap();

    let alert_id = AlertId::new();
    let persisted_alert = PersistedAlert {
        id: alert_id,
        rule_id: RuleId::new("NET-001").unwrap(),
        rule_version: "1.0.0".to_string(),
        severity: AlertSeverity::High,
        title: "Test Port Scan Alert".to_string(),
        description: "Test explanation".to_string(),
        first_seen: now,
        last_seen: now,
        created_at: now,
        updated_at: now,
        status: AlertStatus::Open,
        event_count: 2,
        fingerprint: "NET-001:192.0.2.99".to_string(),
        evidence_event_ids: vec![event1.id, event2.id],
    };

    alert_repo
        .create_alert(&persisted_alert, "system")
        .await
        .expect("created alert");
    assert_eq!(alert_repo.count_alerts().await.unwrap(), 1);

    // Verify evidence retrieval
    let evidence = alert_repo.get_alert_evidence(alert_id).await.unwrap();
    assert_eq!(evidence.len(), 2);
    assert!(evidence.contains(&event1.id));
    assert!(evidence.contains(&event2.id));

    // Verify active alert fingerprint lookup
    let active = alert_repo
        .get_active_alert_by_fingerprint("NET-001:192.0.2.99")
        .await
        .unwrap()
        .expect("active alert found");
    assert_eq!(active.id, alert_id);
    assert_eq!(active.status, AlertStatus::Open);

    // Lifecycle transition: Open -> Acknowledged
    alert_repo
        .acknowledge_alert(alert_id, "analyst_alice", Some("Triaging scanner IP"))
        .await
        .expect("acknowledged alert");

    let acked = alert_repo.get_alert_by_id(alert_id).await.unwrap().unwrap();
    assert_eq!(acked.status, AlertStatus::Acknowledged);

    // Attempting invalid transition: Acknowledged -> Acknowledged
    let err = alert_repo
        .acknowledge_alert(alert_id, "analyst_bob", None)
        .await;
    match err {
        Err(StorageError::InvalidStatusTransition { from, to }) => {
            assert_eq!(from, AlertStatus::Acknowledged);
            assert_eq!(to, AlertStatus::Acknowledged);
        }
        other => panic!("expected InvalidStatusTransition, got {other:?}"),
    }

    // Lifecycle transition: Acknowledged -> Resolved
    alert_repo
        .resolve_alert(
            alert_id,
            "analyst_alice",
            Some("Verified authorized scanner"),
        )
        .await
        .expect("resolved alert");

    let resolved = alert_repo.get_alert_by_id(alert_id).await.unwrap().unwrap();
    assert_eq!(resolved.status, AlertStatus::Resolved);

    // Attempting invalid transition: Resolved -> Resolved or Resolved -> Acknowledged
    let err2 = alert_repo
        .resolve_alert(alert_id, "analyst_bob", None)
        .await;
    assert!(matches!(
        err2,
        Err(StorageError::InvalidStatusTransition { .. })
    ));

    // Verify audit log has entries for create, ack, resolve
    let audit_entries = audit_repo
        .query_entries(&AuditQueryFilter::new().with_target("alert", Some(alert_id.to_string())))
        .await
        .unwrap();
    assert_eq!(audit_entries.len(), 3);
}

#[tokio::test]
async fn test_alert_correlation_upsert() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let event_repo = EventRepository::new(db.pool().clone());
    let alert_repo = AlertRepository::new(db.pool().clone());

    let t1 = Utc::now();
    let e1 = sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)), 80, t1);
    let e2 = sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)), 443, t1);
    event_repo
        .insert_events_batch(&[e1.clone(), e2.clone()])
        .await
        .unwrap();

    let candidate1 = AlertCorrelationCandidate {
        rule_id: RuleId::new("NET-001").unwrap(),
        rule_version: "1.0.0".to_string(),
        severity: AlertSeverity::Medium,
        title: "Port scan from 192.0.2.77".to_string(),
        description: "Initial observation".to_string(),
        first_seen: t1,
        last_seen: t1,
        additional_observation_count: 2,
        fingerprint: "NET-001:192.0.2.77".to_string(),
        evidence_event_ids: vec![e1.id, e2.id],
    };

    let outcome1 = alert_repo
        .upsert_correlated_alert(&candidate1, "detection_engine")
        .await
        .unwrap();

    let CorrelationOutcome::Created(initial_alert_id) = outcome1 else {
        panic!("first candidate must create new alert");
    };

    // Second batch with additional evidence 30 seconds later:
    let t2 = t1 + Duration::seconds(30);
    let e3 = sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)), 8080, t2);
    event_repo.insert_event(&e3).await.unwrap();

    let candidate2 = AlertCorrelationCandidate {
        rule_id: RuleId::new("NET-001").unwrap(),
        rule_version: "1.0.0".to_string(),
        severity: AlertSeverity::High,
        title: "Port scan from 192.0.2.77".to_string(),
        description: "Updated observation".to_string(),
        first_seen: t1,
        last_seen: t2,
        additional_observation_count: 1,
        fingerprint: "NET-001:192.0.2.77".to_string(),
        evidence_event_ids: vec![e3.id],
    };

    let outcome2 = alert_repo
        .upsert_correlated_alert(&candidate2, "detection_engine")
        .await
        .unwrap();

    let CorrelationOutcome::Updated {
        alert_id,
        new_event_count,
        updated_last_seen,
    } = outcome2
    else {
        panic!("second candidate with same fingerprint must update existing active alert");
    };

    assert_eq!(alert_id, initial_alert_id);
    assert_eq!(new_event_count, 3);
    assert_eq!(updated_last_seen, t2);

    // Verify still only 1 active alert in DB
    assert_eq!(alert_repo.count_alerts().await.unwrap(), 1);

    // Verify evidence contains all 3 events
    let evidence = alert_repo
        .get_alert_evidence(initial_alert_id)
        .await
        .unwrap();
    assert_eq!(evidence.len(), 3);
}

#[tokio::test]
async fn test_retention_cleanup_with_evidence_preservation() {
    let db = Database::in_memory().await.expect("in-memory db init");
    let event_repo = EventRepository::new(db.pool().clone());
    let alert_repo = AlertRepository::new(db.pool().clone());
    let retention = RetentionManager::new(db.pool().clone());

    let now = Utc::now();
    let old_timestamp = now - Duration::days(45); // 45 days old (> 30 days retention cutoff)

    // 1. Old event NOT referenced by any alert:
    let old_unlinked_event =
        sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 80, old_timestamp);
    // 2. Old event REFERENCED by an alert:
    let old_linked_event =
        sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 443, old_timestamp);
    // 3. Recent event:
    let recent_event = sample_event(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)), 22, now);

    event_repo
        .insert_events_batch(&[
            old_unlinked_event.clone(),
            old_linked_event.clone(),
            recent_event.clone(),
        ])
        .await
        .unwrap();

    assert_eq!(event_repo.count_events().await.unwrap(), 3);

    // Create an alert linking old_linked_event
    let alert = PersistedAlert {
        id: AlertId::new(),
        rule_id: RuleId::new("NET-001").unwrap(),
        rule_version: "1.0.0".to_string(),
        severity: AlertSeverity::Medium,
        title: "Retained Alert".to_string(),
        description: "Test".to_string(),
        first_seen: old_timestamp,
        last_seen: old_timestamp,
        created_at: old_timestamp,
        updated_at: old_timestamp,
        status: AlertStatus::Open,
        event_count: 1,
        fingerprint: "NET-001:192.0.2.20".to_string(),
        evidence_event_ids: vec![old_linked_event.id],
    };
    alert_repo.create_alert(&alert, "system").await.unwrap();

    // Run retention cycle (default 30 days)
    let policy = RetentionPolicy::default();
    let report = retention
        .run_retention_cycle(&policy, now, "retention_scheduler")
        .await
        .unwrap();

    // Exactly 1 event should have been deleted (old_unlinked_event):
    assert_eq!(report.events_deleted, 1);
    assert_eq!(event_repo.count_events().await.unwrap(), 2);

    // Verify old unlinked event was deleted:
    assert!(
        event_repo
            .get_event_by_id(old_unlinked_event.id)
            .await
            .unwrap()
            .is_none()
    );

    // Verify old linked event was PRESERVED as forensic evidence:
    let preserved = event_repo
        .get_event_by_id(old_linked_event.id)
        .await
        .unwrap();
    assert!(
        preserved.is_some(),
        "supporting alert evidence must not be deleted"
    );

    // Verify recent event was preserved:
    let recent_preserved = event_repo.get_event_by_id(recent_event.id).await.unwrap();
    assert!(
        recent_preserved.is_some(),
        "non-expired events must not be deleted"
    );
}

#[tokio::test]
async fn test_file_backed_database_reopening() {
    let tmp = NamedTempFile::new().expect("temp file");
    let path = tmp.path().to_path_buf();

    let event_id = {
        // Open DB 1
        let config = DatabaseConfig::new(&path);
        let db1 = Database::new(&config).await.expect("db1 init");
        let event_repo = EventRepository::new(db1.pool().clone());

        let event = sample_event(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 9999, Utc::now());
        event_repo.insert_event(&event).await.unwrap();
        db1.close().await;
        event.id
    };

    {
        // Reopen DB 2 from the same file path
        let config = DatabaseConfig::new(&path);
        let db2 = Database::new(&config).await.expect("db2 reopen");
        let event_repo = EventRepository::new(db2.pool().clone());

        let fetched = event_repo
            .get_event_by_id(event_id)
            .await
            .unwrap()
            .expect("event persisted across db reopen");
        assert_eq!(fetched.event.id, event_id);
        assert_eq!(fetched.event.destination_port, Some(9999));
        db2.close().await;
    }
}
