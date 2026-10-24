//! Audit log records, security-relevant operator actions, and audit persistence.

use crate::error::StorageError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tracing::{debug, instrument};
use uuid::Uuid;

/// Default page limit for querying audit log records.
pub const DEFAULT_AUDIT_QUERY_LIMIT: usize = 100;
/// Maximum allowed page limit for querying audit records.
pub const MAX_AUDIT_QUERY_LIMIT: usize = 1000;

/// Structured audit entry representing an operator triage action, configuration change,
/// or system maintenance event (e.g. alert acknowledgement, resolution, or retention run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique audit event identifier.
    pub id: Uuid,
    /// UTC timestamp when the action occurred.
    pub timestamp: DateTime<Utc>,
    /// Actor identity performing the action (e.g., "operator", "system", "analyst").
    pub actor: String,
    /// Action classification (e.g., "alert_created", "alert_acknowledged", "alert_resolved", "retention_cleanup").
    pub action: String,
    /// Classification of the target entity (e.g., "alert", "rule", "retention", "system").
    pub target_type: String,
    /// Optional identifier of the target entity (e.g., AlertId or RuleId).
    pub target_id: Option<String>,
    /// Structured contextual details and notes.
    pub details_json: serde_json::Value,
}

impl AuditEntry {
    /// Creates a new audit entry with a generated UUID and current UTC timestamp.
    #[must_use]
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        target_type: impl Into<String>,
        target_id: Option<String>,
        details_json: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: actor.into(),
            action: action.into(),
            target_type: target_type.into(),
            target_id,
            details_json,
        }
    }
}

/// Bounded query filters for audit log inquiries.
#[derive(Debug, Clone, Default)]
pub struct AuditQueryFilter {
    /// Optional filter by actor name.
    pub actor: Option<String>,
    /// Optional filter by action type.
    pub action: Option<String>,
    /// Optional filter by target entity type.
    pub target_type: Option<String>,
    /// Optional filter by specific target entity ID.
    pub target_id: Option<String>,
    /// Optional start boundary timestamp.
    pub start_time: Option<DateTime<Utc>>,
    /// Optional end boundary timestamp.
    pub end_time: Option<DateTime<Utc>>,
    /// Bounded page limit.
    pub limit: usize,
    /// Offset for pagination.
    pub offset: usize,
}

impl AuditQueryFilter {
    /// Creates a new filter with default bounded limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limit: DEFAULT_AUDIT_QUERY_LIMIT,
            ..Default::default()
        }
    }

    /// Sets the maximum items to return.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.clamp(1, MAX_AUDIT_QUERY_LIMIT);
        self
    }

    /// Sets pagination offset.
    #[must_use]
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Filters by action.
    #[must_use]
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Filters by target.
    #[must_use]
    pub fn with_target(
        mut self,
        target_type: impl Into<String>,
        target_id: Option<String>,
    ) -> Self {
        self.target_type = Some(target_type.into());
        self.target_id = target_id;
        self
    }
}

/// Repository managing durable audit trail persistence and queries in SQLite.
#[derive(Debug, Clone)]
pub struct AuditLogRepository {
    pool: SqlitePool,
}

impl AuditLogRepository {
    /// Creates a new repository instance.
    #[must_use]
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Appends a new audit record.
    ///
    /// # Errors
    /// Returns [`StorageError::Database`] on execution failure.
    #[instrument(skip(self, entry), fields(audit_id = %entry.id, action = %entry.action))]
    pub async fn insert_entry(&self, entry: &AuditEntry) -> Result<(), StorageError> {
        Self::insert_entry_executor(&self.pool, entry).await
    }

    /// Appends an audit entry using the provided transactional executor.
    pub async fn insert_entry_executor<'e, E>(
        executor: E,
        entry: &AuditEntry,
    ) -> Result<(), StorageError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let id_str = entry.id.to_string();
        let timestamp_str = entry.timestamp.to_rfc3339();
        let details_str = serde_json::to_string(&entry.details_json)?;

        sqlx::query(
            r"
            INSERT INTO audit_log (id, timestamp, actor, action, target_type, target_id, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(id_str)
        .bind(timestamp_str)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.target_type)
        .bind(&entry.target_id)
        .bind(details_str)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Queries audit log records matching the bounded filter criteria.
    ///
    /// # Errors
    /// Returns [`StorageError`] on SQL error.
    pub async fn query_entries(
        &self,
        filter: &AuditQueryFilter,
    ) -> Result<Vec<AuditEntry>, StorageError> {
        let limit = if filter.limit == 0 {
            DEFAULT_AUDIT_QUERY_LIMIT
        } else {
            filter.limit.clamp(1, MAX_AUDIT_QUERY_LIMIT)
        };

        let mut sql = String::from(
            r"
            SELECT id, timestamp, actor, action, target_type, target_id, details_json
            FROM audit_log
            WHERE 1=1
            ",
        );

        let mut binds: Vec<String> = Vec::new();

        if let Some(actor) = &filter.actor {
            sql.push_str(" AND actor = ?");
            binds.push(actor.clone());
        }

        if let Some(action) = &filter.action {
            sql.push_str(" AND action = ?");
            binds.push(action.clone());
        }

        if let Some(target_type) = &filter.target_type {
            sql.push_str(" AND target_type = ?");
            binds.push(target_type.clone());
        }

        if let Some(target_id) = &filter.target_id {
            sql.push_str(" AND target_id = ?");
            binds.push(target_id.clone());
        }

        if let Some(start) = filter.start_time {
            sql.push_str(" AND timestamp >= ?");
            binds.push(start.to_rfc3339());
        }

        if let Some(end) = filter.end_time {
            sql.push_str(" AND timestamp <= ?");
            binds.push(end.to_rfc3339());
        }

        sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

        let mut query = sqlx::query(&sql);
        for bind in binds {
            query = query.bind(bind);
        }
        query = query.bind(limit as i64).bind(filter.offset as i64);

        let rows = query.fetch_all(&self.pool).await?;
        let mut entries = Vec::with_capacity(rows.len());

        for row in rows {
            let id_str: String = row.try_get("id")?;
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| StorageError::InvalidParameter(format!("invalid audit id: {e}")))?;

            let ts_str: String = row.try_get("timestamp")?;
            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map_err(|e| StorageError::InvalidParameter(format!("invalid timestamp: {e}")))?
                .with_timezone(&Utc);

            let actor: String = row.try_get("actor")?;
            let action: String = row.try_get("action")?;
            let target_type: String = row.try_get("target_type")?;
            let target_id: Option<String> = row.try_get("target_id")?;
            let details_str: String = row.try_get("details_json")?;
            let details_json: serde_json::Value = serde_json::from_str(&details_str)?;

            entries.push(AuditEntry {
                id,
                timestamp,
                actor,
                action,
                target_type,
                target_id,
                details_json,
            });
        }

        Ok(entries)
    }

    /// Returns the total count of audit log records.
    pub async fn count_entries(&self) -> Result<usize, StorageError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.max(0) as usize)
    }

    /// Counts audit log records matching the bounded filter criteria.
    pub async fn count_matching_entries(
        &self,
        filter: &AuditQueryFilter,
    ) -> Result<usize, StorageError> {
        let mut sql = String::from("SELECT COUNT(*) FROM audit_log WHERE 1=1");
        let mut binds: Vec<String> = Vec::new();

        if let Some(actor) = &filter.actor {
            sql.push_str(" AND actor = ?");
            binds.push(actor.clone());
        }

        if let Some(action) = &filter.action {
            sql.push_str(" AND action = ?");
            binds.push(action.clone());
        }

        if let Some(target_type) = &filter.target_type {
            sql.push_str(" AND target_type = ?");
            binds.push(target_type.clone());
        }

        if let Some(target_id) = &filter.target_id {
            sql.push_str(" AND target_id = ?");
            binds.push(target_id.clone());
        }

        if let Some(start) = filter.start_time {
            sql.push_str(" AND timestamp >= ?");
            binds.push(start.to_rfc3339());
        }

        if let Some(end) = filter.end_time {
            sql.push_str(" AND timestamp <= ?");
            binds.push(end.to_rfc3339());
        }

        let mut query = sqlx::query_scalar::<_, i64>(&sql);
        for bind in binds {
            query = query.bind(bind);
        }

        let count = query.fetch_one(&self.pool).await?;
        Ok(count.max(0) as usize)
    }

    /// Deletes expired audit log records older than `cutoff` in a single bounded batch.
    pub async fn delete_expired_entries(
        &self,
        cutoff: DateTime<Utc>,
        max_delete: usize,
    ) -> Result<usize, StorageError> {
        let cutoff_str = cutoff.to_rfc3339();
        let limit = max_delete.clamp(1, 10_000) as i64;

        let result = sqlx::query(
            r"
            DELETE FROM audit_log
            WHERE id IN (
                SELECT id FROM audit_log
                WHERE timestamp < ?
                LIMIT ?
            )
            ",
        )
        .bind(cutoff_str)
        .bind(limit)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected() as usize;
        debug!(deleted, "Deleted expired audit log entries");
        Ok(deleted)
    }
}
