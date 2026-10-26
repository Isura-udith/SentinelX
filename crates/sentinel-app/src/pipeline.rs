//! End-to-end telemetry ingestion, persistent storage, stateful analytical detection,
//! and alert correlation pipeline coordinator.

use anyhow::{Context, Result};
use chrono::Utc;
use sentinel_collector::error::CollectorError;
use sentinel_collector::source::{CollectionBatch, StandbyCollector, TelemetryCollector};
use sentinel_collector::stats::CollectionStats;
use sentinel_core::alert::SecurityAlert;
use sentinel_detection::engine::DetectionEngine;
use sentinel_storage::alerts::{AlertCorrelationCandidate, CorrelationOutcome};
use sentinel_storage::retention::{RetentionPolicy, RetentionReport};
use sentinel_storage::{
    AlertRepository, AuditLogRepository, Database, EventRepository, RetentionManager, StorageError,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

/// Structured metrics tracking persistence and detection pipeline reliability.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    /// Total count of network events successfully persisted to SQLite.
    pub events_ingested: AtomicUsize,
    /// Count of duplicate events ignored during batch ingestion.
    pub events_duplicated: AtomicUsize,
    /// Total duration spent executing batch insertion transactions (milliseconds).
    pub batch_insertion_duration_ms: AtomicU64,
    /// Count of database failures or rollbacks encountered.
    pub database_errors: AtomicUsize,
    /// Total duration spent evaluating detection rules (milliseconds).
    pub detection_duration_ms: AtomicU64,
    /// Total count of newly created active security alerts.
    pub alerts_created: AtomicUsize,
    /// Total count of existing active alerts updated with correlated evidence.
    pub alerts_correlated: AtomicUsize,
    /// Count of expired events purged during retention cycles.
    pub retention_deletions: AtomicUsize,
}

impl std::fmt::Display for PipelineMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Pipeline Persistence & Detection Metrics:")?;
        writeln!(
            f,
            "  Events Persisted to SQLite : {}",
            self.events_ingested.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "  Duplicate Events Skipped   : {}",
            self.events_duplicated.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "  Batch Insert Time (Total)  : {} ms",
            self.batch_insertion_duration_ms.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "  Database Errors            : {}",
            self.database_errors.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "  Detection Evaluation Time  : {} ms",
            self.detection_duration_ms.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "  Security Alerts Created    : {}",
            self.alerts_created.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "  Security Alerts Correlated : {}",
            self.alerts_correlated.load(Ordering::Relaxed)
        )?;
        write!(
            f,
            "  Retention Purged Events    : {}",
            self.retention_deletions.load(Ordering::Relaxed)
        )
    }
}

/// Pipeline configuration options.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Software and rule version string.
    pub version: String,
    /// Actor identifier recorded in audit log records.
    pub operator_actor: String,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            version: "0.3.0".to_string(),
            operator_actor: "sentinel_daemon".to_string(),
        }
    }
}

/// End-to-end pipeline coordinator orchestrating:
/// Telemetry Capture -> Normalization -> SQLite Event Persistence -> Stateful Detection ->
/// Alert Correlation -> Alert & Evidence Persistence -> Audit Trail.
pub struct PipelineCoordinator {
    config: PipelineConfig,
    collector: Box<dyn TelemetryCollector>,
    database: Database,
    event_repo: EventRepository,
    alert_repo: AlertRepository,
    audit_repo: AuditLogRepository,
    retention_mgr: RetentionManager,
    engine: DetectionEngine,
    collection_stats: CollectionStats,
    metrics: Arc<PipelineMetrics>,
}

impl PipelineCoordinator {
    /// Creates a new `PipelineCoordinator` instance.
    #[must_use]
    pub fn new(
        config: PipelineConfig,
        collector: Box<dyn TelemetryCollector>,
        database: Database,
        engine: DetectionEngine,
    ) -> Self {
        let pool = database.pool().clone();
        Self {
            config,
            collector,
            database,
            event_repo: EventRepository::new(pool.clone()),
            alert_repo: AlertRepository::new(pool.clone()),
            audit_repo: AuditLogRepository::new(pool.clone()),
            retention_mgr: RetentionManager::new(pool),
            engine,
            collection_stats: CollectionStats::new(),
            metrics: Arc::new(PipelineMetrics::default()),
        }
    }

    /// Returns a reference to the pipeline performance metrics.
    #[must_use]
    pub fn metrics(&self) -> Arc<PipelineMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Returns a reference to the collection statistics.
    #[must_use]
    pub const fn collection_stats(&self) -> &CollectionStats {
        &self.collection_stats
    }

    /// Returns a reference to the underlying database.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Returns a reference to the alert repository.
    #[must_use]
    pub const fn alert_repo(&self) -> &AlertRepository {
        &self.alert_repo
    }

    /// Returns a reference to the audit log repository.
    #[must_use]
    pub const fn audit_repo(&self) -> &AuditLogRepository {
        &self.audit_repo
    }

    /// Returns a reference to the event repository.
    #[must_use]
    pub const fn event_repo(&self) -> &EventRepository {
        &self.event_repo
    }

    /// Replaces the active telemetry collector instance.
    pub fn set_collector(&mut self, collector: Box<dyn TelemetryCollector>) {
        self.collector = collector;
    }

    /// Replaces the active detection engine with updated rules/configuration.
    pub fn update_engine(&mut self, engine: DetectionEngine) {
        self.engine = engine;
    }

    /// Executes a single complete end-to-end processing cycle.
    #[allow(clippy::too_many_lines)]
    #[instrument(skip(self))]
    pub async fn process_cycle(&mut self) -> Result<Vec<SecurityAlert>> {
        // 1. Capture snapshot telemetry across the spawn_blocking boundary
        let mut collector = std::mem::replace(&mut self.collector, Box::new(StandbyCollector));
        let collection_start = Instant::now();

        let collection_result: Result<CollectionBatch, CollectorError> =
            tokio::task::spawn_blocking(move || {
                let res = collector.collect();
                (res, collector)
            })
            .await
            .map(|(res, returned_collector)| {
                self.collector = returned_collector;
                res
            })
            .context("tokio worker thread panicked during telemetry capture")?;

        let collection_duration = collection_start.elapsed();

        let batch = match collection_result {
            Ok(batch) => {
                self.collection_stats.record_success(
                    batch.metadata.raw_records_observed,
                    batch.metadata.normalized_events_produced,
                    batch.metadata.records_skipped,
                    batch.metadata.duration,
                );
                batch
            }
            Err(err) => {
                self.collection_stats.record_failure(collection_duration);
                error!(error = %err, "Telemetry capture failed during cycle");
                return Err(err.into());
            }
        };

        if batch.events.is_empty() {
            debug!("Collection snapshot produced 0 events; skipping persistence and detection");
            return Ok(Vec::new());
        }

        // 2. Persist event batch to SQLite transactionally (Section 10)
        let insert_start = Instant::now();
        match self.event_repo.insert_events_batch(&batch.events).await {
            Ok(res) => {
                let insert_elapsed = insert_start.elapsed();
                self.metrics
                    .events_ingested
                    .fetch_add(res.inserted_count, Ordering::Relaxed);
                self.metrics
                    .events_duplicated
                    .fetch_add(res.duplicate_count, Ordering::Relaxed);
                let insert_ms = u64::try_from(insert_elapsed.as_millis()).unwrap_or(u64::MAX);
                self.metrics
                    .batch_insertion_duration_ms
                    .fetch_add(insert_ms, Ordering::Relaxed);

                debug!(
                    inserted = res.inserted_count,
                    duplicates = res.duplicate_count,
                    duration = ?insert_elapsed,
                    "Persisted event batch to SQLite"
                );
            }
            Err(db_err) => {
                self.metrics.database_errors.fetch_add(1, Ordering::Relaxed);
                error!(error = %db_err, "Database batch insert failed; transaction rolled back");
                return Err(db_err.into());
            }
        }

        // 3. Stateful Detection Engine Analysis (Sections 11, 12, 13)
        let detection_start = Instant::now();
        let detected_alerts = match self.engine.process_batch(&batch.events) {
            Ok(alerts) => {
                let detection_elapsed = detection_start.elapsed();
                let detection_ms = u64::try_from(detection_elapsed.as_millis()).unwrap_or(u64::MAX);
                self.metrics
                    .detection_duration_ms
                    .fetch_add(detection_ms, Ordering::Relaxed);
                self.collection_stats.record_alerts(alerts.len());
                alerts
            }
            Err(detection_err) => {
                error!(error = %detection_err, "Detection engine rule evaluation failed");
                return Err(detection_err.into());
            }
        };

        if detected_alerts.is_empty() {
            return Ok(Vec::new());
        }

        // 4. Alert Correlation and Durable Evidence Persistence (Section 14)
        let mut successfully_persisted_alerts = Vec::new();
        for alert in &detected_alerts {
            let src_str = alert
                .source_ip
                .map_or_else(|| "none".to_string(), |ip| ip.to_string());
            let fingerprint = format!("{}:{}", alert.rule_id, src_str);

            let candidate = AlertCorrelationCandidate {
                rule_id: alert.rule_id.clone(),
                rule_version: self.config.version.clone(),
                severity: alert.severity,
                title: alert.title.clone(),
                description: alert.explanation.clone(),
                first_seen: alert.first_observed_at,
                last_seen: alert.last_observed_at,
                additional_observation_count: alert.observation_count,
                fingerprint: fingerprint.clone(),
                evidence_event_ids: alert.evidence_event_ids.clone(),
            };

            match self
                .alert_repo
                .upsert_correlated_alert(&candidate, &self.config.operator_actor)
                .await
            {
                Ok(CorrelationOutcome::Created(new_id)) => {
                    self.metrics.alerts_created.fetch_add(1, Ordering::Relaxed);
                    info!(
                        alert_id = %new_id,
                        rule_id = %alert.rule_id,
                        severity = %alert.severity,
                        "Created new persistent security alert"
                    );
                    let mut persisted = alert.clone();
                    persisted.id = new_id;
                    successfully_persisted_alerts.push(persisted);
                }
                Ok(CorrelationOutcome::Updated {
                    alert_id,
                    new_event_count,
                    updated_last_seen,
                }) => {
                    self.metrics
                        .alerts_correlated
                        .fetch_add(1, Ordering::Relaxed);
                    info!(
                        alert_id = %alert_id,
                        event_count = new_event_count,
                        last_seen = %updated_last_seen,
                        "Updated existing active security alert with correlated evidence"
                    );
                    let mut persisted = alert.clone();
                    persisted.id = alert_id;
                    successfully_persisted_alerts.push(persisted);
                }
                Err(err) => {
                    self.metrics.database_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(error = %err, fingerprint = %fingerprint, "Failed to correlate alert");
                }
            }
        }

        Ok(successfully_persisted_alerts)
    }

    /// Executes an explicit retention cleanup cycle.
    pub async fn run_retention(
        &self,
        policy: &RetentionPolicy,
    ) -> Result<RetentionReport, StorageError> {
        let now = Utc::now();
        let report = self
            .retention_mgr
            .run_retention_cycle(policy, now, &self.config.operator_actor)
            .await?;
        self.metrics
            .retention_deletions
            .fetch_add(report.events_deleted, Ordering::Relaxed);
        Ok(report)
    }
}
