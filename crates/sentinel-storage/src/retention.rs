//! Configurable data retention policies, foreign-key safe evidence preservation,
//! and batched cleanup execution.

use crate::audit::{AuditEntry, AuditLogRepository};
use crate::error::StorageError;
use crate::events::EventRepository;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::time::Instant;
use tracing::{info, instrument};

/// Default retention period for general telemetry network events (30 days).
pub const DEFAULT_EVENT_RETENTION_DAYS: u32 = 30;
/// Default retention period for security audit log entries (90 days).
pub const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 90;
/// Default batch size for deletion transactions to limit SQLite write-lock duration.
pub const DEFAULT_RETENTION_BATCH_SIZE: usize = 500;
/// Default maximum batches to execute per retention run to prevent starvation.
pub const DEFAULT_MAX_RETENTION_BATCHES: usize = 100;

/// Configuration governing automated retention cleanup cycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Number of days to retain general network events before deletion.
    pub event_retention_days: u32,
    /// Number of days to retain security audit log entries before deletion.
    pub audit_retention_days: u32,
    /// Batch size for chunked SQL deletions.
    pub batch_size: usize,
    /// Maximum number of batches to process in a single cleanup cycle.
    pub max_batches_per_run: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            event_retention_days: DEFAULT_EVENT_RETENTION_DAYS,
            audit_retention_days: DEFAULT_AUDIT_RETENTION_DAYS,
            batch_size: DEFAULT_RETENTION_BATCH_SIZE,
            max_batches_per_run: DEFAULT_MAX_RETENTION_BATCHES,
        }
    }
}

impl RetentionPolicy {
    /// Constructs a new [`RetentionPolicy`].
    #[must_use]
    pub fn new(
        event_retention_days: u32,
        audit_retention_days: u32,
        batch_size: usize,
        max_batches_per_run: usize,
    ) -> Self {
        Self {
            event_retention_days,
            audit_retention_days,
            batch_size: batch_size.clamp(1, 10_000),
            max_batches_per_run: max_batches_per_run.clamp(1, 1_000),
        }
    }
}

/// Execution summary report detailing the outcome of a retention cleanup cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionReport {
    /// Total count of expired network events purged.
    pub events_deleted: usize,
    /// Total count of expired audit log records purged.
    pub audit_entries_deleted: usize,
    /// Number of deletion batches executed.
    pub batches_executed: usize,
    /// Total wall-clock duration of the retention cycle.
    pub duration: std::time::Duration,
}

/// Retention manager executing foreign-key-safe data cleanup according to configured policies.
#[derive(Debug, Clone)]
pub struct RetentionManager {
    pool: SqlitePool,
    events: EventRepository,
    audit: AuditLogRepository,
}

impl RetentionManager {
    /// Creates a new `RetentionManager`.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            events: EventRepository::new(pool.clone()),
            audit: AuditLogRepository::new(pool.clone()),
            pool,
        }
    }

    /// Returns a reference to the database connection pool.
    #[must_use]
    pub const fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Executes a complete retention cleanup cycle.
    ///
    /// Evidence Preservation Guarantee:
    /// Any network event referenced in `alert_events` as forensic evidence for an alert
    /// is **strictly preserved** and never deleted, regardless of age.
    ///
    /// # Errors
    /// Returns [`StorageError`] if database operations encounter failures.
    #[instrument(skip(self, policy), fields(actor))]
    pub async fn run_retention_cycle(
        &self,
        policy: &RetentionPolicy,
        now: DateTime<Utc>,
        actor: &str,
    ) -> Result<RetentionReport, StorageError> {
        let start = Instant::now();
        let event_cutoff = now - Duration::days(i64::from(policy.event_retention_days));
        let audit_cutoff = now - Duration::days(i64::from(policy.audit_retention_days));

        let mut total_events_deleted = 0;
        let mut batches_executed = 0;

        // 1. Purge expired events in bounded chunks
        loop {
            if batches_executed >= policy.max_batches_per_run {
                info!("Reached maximum retention batches limit; pausing event purge");
                break;
            }

            let deleted = self
                .events
                .delete_expired_events(event_cutoff, policy.batch_size)
                .await?;

            batches_executed += 1;
            total_events_deleted += deleted;

            if deleted == 0 || deleted < policy.batch_size {
                break;
            }
        }

        // 2. Purge expired audit log records in bounded chunks
        let mut total_audit_deleted = 0;
        loop {
            if batches_executed >= policy.max_batches_per_run * 2 {
                break;
            }

            let deleted = self
                .audit
                .delete_expired_entries(audit_cutoff, policy.batch_size)
                .await?;

            batches_executed += 1;
            total_audit_deleted += deleted;

            if deleted == 0 || deleted < policy.batch_size {
                break;
            }
        }

        let elapsed = start.elapsed();
        let report = RetentionReport {
            events_deleted: total_events_deleted,
            audit_entries_deleted: total_audit_deleted,
            batches_executed,
            duration: elapsed,
        };

        // Record audit entry for this retention execution
        let audit = AuditEntry::new(
            actor,
            "retention_cleanup",
            "retention",
            None,
            serde_json::json!({
                "events_deleted": total_events_deleted,
                "audit_entries_deleted": total_audit_deleted,
                "batches_executed": batches_executed,
                "duration_ms": elapsed.as_millis(),
                "event_cutoff": event_cutoff.to_rfc3339(),
                "audit_cutoff": audit_cutoff.to_rfc3339(),
            }),
        );
        self.audit.insert_entry(&audit).await?;

        info!(
            events_deleted = total_events_deleted,
            audit_deleted = total_audit_deleted,
            duration = ?elapsed,
            "Retention cleanup cycle completed successfully"
        );

        Ok(report)
    }
}
