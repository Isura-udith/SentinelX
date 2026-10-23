//! Security alert persistence, alert-event evidence linking, stateful status transitions,
//! alert correlation, and fingerprint deduplication.

use crate::audit::{AuditEntry, AuditLogRepository};
use crate::error::StorageError;
use chrono::{DateTime, Utc};
use sentinel_core::alert::{
    AlertId, AlertSeverity, AlertStatus, RuleId, SecurityAlert, SecurityAlertBuilder,
};
use sentinel_core::event::EventId;
use sqlx::{Row, SqlitePool};
use std::net::IpAddr;
use tracing::{debug, info, instrument};
use uuid::Uuid;

/// Default page limit for querying alerts.
pub const DEFAULT_ALERT_QUERY_LIMIT: usize = 50;
/// Maximum allowed page limit for querying alerts.
pub const MAX_ALERT_QUERY_LIMIT: usize = 500;

/// Persisted security alert entity stored in the SQLite `alerts` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedAlert {
    /// Unique identifier for this alert.
    pub id: AlertId,
    /// Identifier of the detection rule that produced the alert.
    pub rule_id: RuleId,
    /// Software or rule logic version.
    pub rule_version: String,
    /// Assessed severity level.
    pub severity: AlertSeverity,
    /// Short human-readable title.
    pub title: String,
    /// Explanation describing the anomalous telemetry pattern and context.
    pub description: String,
    /// Earliest observed evidence observation timestamp.
    pub first_seen: DateTime<Utc>,
    /// Most recent observed evidence observation timestamp.
    pub last_seen: DateTime<Utc>,
    /// UTC timestamp when the alert record was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp when the alert record was last modified.
    pub updated_at: DateTime<Utc>,
    /// Operational triage status.
    pub status: AlertStatus,
    /// Cumulative count of matching connection observations.
    pub event_count: usize,
    /// Stable correlation grouping key (fingerprint).
    pub fingerprint: String,
    /// Supporting evidence event identifiers.
    pub evidence_event_ids: Vec<EventId>,
}

impl PersistedAlert {
    /// Converts this persisted alert into a domain [`SecurityAlert`].
    #[must_use]
    pub fn to_security_alert(&self, source_ip: Option<IpAddr>) -> SecurityAlert {
        let mut builder = SecurityAlertBuilder::new(
            self.rule_id.clone(),
            self.severity,
            self.title.clone(),
            self.description.clone(),
            self.first_seen,
            self.last_seen,
        )
        .with_id(self.id)
        .with_observation_count(self.event_count)
        .with_status(self.status);

        if let Some(ip) = source_ip {
            builder = builder.with_source_ip(ip);
        }

        builder = builder.with_evidence_ids(self.evidence_event_ids.clone());

        builder.build().unwrap_or_else(|_| SecurityAlert {
            id: self.id,
            rule_id: self.rule_id.clone(),
            severity: self.severity,
            title: self.title.clone(),
            explanation: self.description.clone(),
            first_observed_at: self.first_seen,
            last_observed_at: self.last_seen,
            observation_count: self.event_count.max(self.evidence_event_ids.len()),
            source_ip,
            evidence_event_ids: self.evidence_event_ids.clone(),
            status: self.status,
        })
    }

    /// Constructs a `PersistedAlert` from a domain [`SecurityAlert`], rule version, and fingerprint.
    #[must_use]
    pub fn from_security_alert(
        alert: &SecurityAlert,
        rule_version: impl Into<String>,
        fingerprint: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: alert.id,
            rule_id: alert.rule_id.clone(),
            rule_version: rule_version.into(),
            severity: alert.severity,
            title: alert.title.clone(),
            description: alert.explanation.clone(),
            first_seen: alert.first_observed_at,
            last_seen: alert.last_observed_at,
            created_at: now,
            updated_at: now,
            status: alert.status,
            event_count: alert.observation_count,
            fingerprint: fingerprint.into(),
            evidence_event_ids: alert.evidence_event_ids.clone(),
        }
    }
}

/// Candidate update to be correlated against active alerts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertCorrelationCandidate {
    /// Detection rule identifier.
    pub rule_id: RuleId,
    /// Software or rule logic version.
    pub rule_version: String,
    /// Evaluated severity.
    pub severity: AlertSeverity,
    /// Display title.
    pub title: String,
    /// Technical description.
    pub description: String,
    /// Earliest observed evidence in candidate batch.
    pub first_seen: DateTime<Utc>,
    /// Latest observed evidence in candidate batch.
    pub last_seen: DateTime<Utc>,
    /// Number of new observations in the current batch.
    pub additional_observation_count: usize,
    /// Stable fingerprint for correlation.
    pub fingerprint: String,
    /// Evidence IDs from current batch.
    pub evidence_event_ids: Vec<EventId>,
}

/// Result of an alert correlation evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationOutcome {
    /// A new open alert was created.
    Created(AlertId),
    /// An existing active alert was updated with new evidence and timestamp.
    Updated {
        /// ID of the updated active alert.
        alert_id: AlertId,
        /// New cumulative event count.
        new_event_count: usize,
        /// Advanced last-seen timestamp.
        updated_last_seen: DateTime<Utc>,
    },
}

/// Bounded query filter for retrieving persisted alerts.
#[derive(Debug, Clone, Default)]
pub struct AlertQueryFilter {
    /// Optional filter by status.
    pub status: Option<AlertStatus>,
    /// Optional filter by rule ID string.
    pub rule_id: Option<String>,
    /// Optional filter by severity.
    pub severity: Option<AlertSeverity>,
    /// Optional filter by earliest creation time.
    pub start_time: Option<DateTime<Utc>>,
    /// Optional filter by latest creation time.
    pub end_time: Option<DateTime<Utc>>,
    /// Page size limit (clamped to `MAX_ALERT_QUERY_LIMIT`).
    pub limit: usize,
    /// Offset for pagination.
    pub offset: usize,
}

impl AlertQueryFilter {
    /// Creates a query filter with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limit: DEFAULT_ALERT_QUERY_LIMIT,
            ..Default::default()
        }
    }

    /// Sets the maximum items to return.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.clamp(1, MAX_ALERT_QUERY_LIMIT);
        self
    }

    /// Sets pagination offset.
    #[must_use]
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Filters by status.
    #[must_use]
    pub fn with_status(mut self, status: AlertStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filters by rule ID.
    #[must_use]
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// Filters by severity.
    #[must_use]
    pub fn with_severity(mut self, severity: AlertSeverity) -> Self {
        self.severity = Some(severity);
        self
    }
}

/// Repository providing CRUD operations, evidence linking, alert correlation,
/// and triage lifecycle persistence for security alerts.
#[derive(Debug, Clone)]
pub struct AlertRepository {
    pool: SqlitePool,
}

impl AlertRepository {
    /// Creates an `AlertRepository` using the provided pool.
    #[must_use]
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Persists a new security alert record along with its evidence links and an initial audit entry.
    ///
    /// # Errors
    /// Returns [`StorageError::ConstraintViolation`] if an active alert with the same fingerprint
    /// already exists, or other [`StorageError`] on SQL failures.
    #[instrument(skip(self, alert), fields(alert_id = %alert.id, fingerprint = %alert.fingerprint))]
    pub async fn create_alert(
        &self,
        alert: &PersistedAlert,
        actor: &str,
    ) -> Result<AlertId, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;

        let id_str = alert.id.to_string();
        let rule_id_str = alert.rule_id.as_str();
        let severity_str = severity_to_str(alert.severity);
        let status_str = status_to_str(alert.status);
        let first_seen_str = alert.first_seen.to_rfc3339();
        let last_seen_str = alert.last_seen.to_rfc3339();
        let created_at_str = alert.created_at.to_rfc3339();
        let updated_at_str = alert.updated_at.to_rfc3339();

        let insert_query = sqlx::query(
            r"
            INSERT INTO alerts (
                id, rule_id, rule_version, severity, title, description,
                first_seen, last_seen, created_at, updated_at, status, event_count, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(&id_str)
        .bind(rule_id_str)
        .bind(&alert.rule_version)
        .bind(severity_str)
        .bind(&alert.title)
        .bind(&alert.description)
        .bind(first_seen_str)
        .bind(last_seen_str)
        .bind(created_at_str)
        .bind(updated_at_str)
        .bind(status_str)
        .bind(alert.event_count as i64)
        .bind(&alert.fingerprint);

        if let Err(e) = insert_query.execute(&mut *tx).await {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.is_unique_violation()
            {
                return Err(StorageError::ConstraintViolation(format!(
                    "active alert with fingerprint '{}' already exists",
                    alert.fingerprint
                )));
            }
            return Err(StorageError::Database(e));
        }

        // Link evidence event IDs
        let linked_at_str = alert.created_at.to_rfc3339();
        for &eid in &alert.evidence_event_ids {
            sqlx::query(
                r"
                INSERT OR IGNORE INTO alert_events (alert_id, event_id, linked_at)
                VALUES (?, ?, ?)
                ",
            )
            .bind(&id_str)
            .bind(eid.to_string())
            .bind(&linked_at_str)
            .execute(&mut *tx)
            .await?;
        }

        // Record audit entry
        let audit = AuditEntry::new(
            actor,
            "alert_created",
            "alert",
            Some(id_str.clone()),
            serde_json::json!({
                "rule_id": rule_id_str,
                "severity": severity_str,
                "title": alert.title,
                "fingerprint": alert.fingerprint,
                "event_count": alert.event_count,
            }),
        );
        AuditLogRepository::insert_entry_executor(&mut *tx, &audit).await?;

        tx.commit().await.map_err(StorageError::Database)?;
        info!(alert_id = %alert.id, "Security alert persisted successfully");
        Ok(alert.id)
    }

    /// Fetches an alert by ID, including its associated evidence event IDs.
    #[instrument(skip(self), fields(alert_id = %id))]
    pub async fn get_alert_by_id(
        &self,
        id: AlertId,
    ) -> Result<Option<PersistedAlert>, StorageError> {
        let id_str = id.to_string();
        let row = sqlx::query(
            r"
            SELECT id, rule_id, rule_version, severity, title, description,
                   first_seen, last_seen, created_at, updated_at, status, event_count, fingerprint
            FROM alerts
            WHERE id = ?
            ",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let evidence_event_ids = self.get_alert_evidence(id).await?;
        let alert = map_alert_row(&row, evidence_event_ids)?;
        Ok(Some(alert))
    }

    /// Retrieves an active (open or acknowledged) alert matching the stable fingerprint, if one exists.
    #[instrument(skip(self), fields(fingerprint))]
    pub async fn get_active_alert_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<PersistedAlert>, StorageError> {
        let row = sqlx::query(
            r"
            SELECT id, rule_id, rule_version, severity, title, description,
                   first_seen, last_seen, created_at, updated_at, status, event_count, fingerprint
            FROM alerts
            WHERE fingerprint = ? AND status IN ('open', 'acknowledged')
            LIMIT 1
            ",
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id_str: String = row.try_get("id")?;
        let aid = AlertId::from_uuid(
            Uuid::parse_str(&id_str)
                .map_err(|e| StorageError::InvalidParameter(format!("invalid alert uuid: {e}")))?,
        );

        let evidence_event_ids = self.get_alert_evidence(aid).await?;
        let alert = map_alert_row(&row, evidence_event_ids)?;
        Ok(Some(alert))
    }

    /// Correlates new detection evidence against active alerts.
    ///
    /// If an active alert matching the fingerprint exists, it is updated transactionally:
    /// - `last_seen` is updated to the newer evidence observation timestamp.
    /// - `event_count` is incremented.
    /// - New evidence IDs are linked.
    /// - An audit log entry is written.
    ///
    /// If no active alert exists (or previous alerts with the same fingerprint were resolved),
    /// a new open alert is created.
    #[allow(clippy::too_many_lines)]
    #[instrument(skip(self, candidate), fields(fingerprint = %candidate.fingerprint))]
    pub async fn upsert_correlated_alert(
        &self,
        candidate: &AlertCorrelationCandidate,
        actor: &str,
    ) -> Result<CorrelationOutcome, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;

        let active_row = sqlx::query(
            r"
            SELECT id, first_seen, last_seen, event_count, severity, status
            FROM alerts
            WHERE fingerprint = ? AND status IN ('open', 'acknowledged')
            LIMIT 1
            ",
        )
        .bind(&candidate.fingerprint)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = active_row {
            let id_str: String = row.try_get("id")?;
            let alert_id =
                AlertId::from_uuid(Uuid::parse_str(&id_str).map_err(|e| {
                    StorageError::InvalidParameter(format!("invalid alert uuid: {e}"))
                })?);

            let existing_last_seen_str: String = row.try_get("last_seen")?;
            let existing_last_seen = DateTime::parse_from_rfc3339(&existing_last_seen_str)
                .map_err(|e| StorageError::InvalidParameter(format!("invalid last_seen: {e}")))?
                .with_timezone(&Utc);

            let existing_count: i64 = row.try_get("event_count")?;
            let new_count =
                (existing_count as usize).saturating_add(candidate.additional_observation_count);

            let new_last_seen = existing_last_seen.max(candidate.last_seen);
            let now = Utc::now();

            sqlx::query(
                r"
                UPDATE alerts
                SET last_seen = ?,
                    event_count = ?,
                    updated_at = ?
                WHERE id = ?
                ",
            )
            .bind(new_last_seen.to_rfc3339())
            .bind(new_count as i64)
            .bind(now.to_rfc3339())
            .bind(&id_str)
            .execute(&mut *tx)
            .await?;

            // Link any new evidence IDs
            let linked_at_str = now.to_rfc3339();
            for &eid in &candidate.evidence_event_ids {
                sqlx::query(
                    r"
                    INSERT OR IGNORE INTO alert_events (alert_id, event_id, linked_at)
                    VALUES (?, ?, ?)
                    ",
                )
                .bind(&id_str)
                .bind(eid.to_string())
                .bind(&linked_at_str)
                .execute(&mut *tx)
                .await?;
            }

            let audit = AuditEntry::new(
                actor,
                "alert_correlated",
                "alert",
                Some(id_str),
                serde_json::json!({
                    "fingerprint": candidate.fingerprint,
                    "added_observations": candidate.additional_observation_count,
                    "new_event_count": new_count,
                    "new_last_seen": new_last_seen.to_rfc3339(),
                }),
            );
            AuditLogRepository::insert_entry_executor(&mut *tx, &audit).await?;

            tx.commit().await.map_err(StorageError::Database)?;
            debug!(alert_id = %alert_id, new_count, "Correlated into existing active alert");

            Ok(CorrelationOutcome::Updated {
                alert_id,
                new_event_count: new_count,
                updated_last_seen: new_last_seen,
            })
        } else {
            // No active alert exists for this fingerprint: create a new one
            let new_id = AlertId::new();
            let id_str = new_id.to_string();
            let now = Utc::now();
            let severity_str = severity_to_str(candidate.severity);
            let rule_id_str = candidate.rule_id.as_str();

            let insert_res = sqlx::query(
                r"
                INSERT INTO alerts (
                    id, rule_id, rule_version, severity, title, description,
                    first_seen, last_seen, created_at, updated_at, status, event_count, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                ",
            )
            .bind(&id_str)
            .bind(rule_id_str)
            .bind(&candidate.rule_version)
            .bind(severity_str)
            .bind(&candidate.title)
            .bind(&candidate.description)
            .bind(candidate.first_seen.to_rfc3339())
            .bind(candidate.last_seen.to_rfc3339())
            .bind(now.to_rfc3339())
            .bind(now.to_rfc3339())
            .bind(candidate.additional_observation_count as i64)
            .bind(&candidate.fingerprint)
            .execute(&mut *tx)
            .await;

            if let Err(e) = insert_res {
                if let sqlx::Error::Database(ref db_err) = e
                    && db_err.is_unique_violation()
                {
                    let _ = tx.rollback().await;
                    debug!(fingerprint = %candidate.fingerprint, "Concurrent active alert detected; retrying correlation");
                    return Box::pin(self.upsert_correlated_alert(candidate, actor)).await;
                }
                return Err(StorageError::Database(e));
            }

            let linked_at_str = now.to_rfc3339();
            for &eid in &candidate.evidence_event_ids {
                sqlx::query(
                    r"
                    INSERT OR IGNORE INTO alert_events (alert_id, event_id, linked_at)
                    VALUES (?, ?, ?)
                    ",
                )
                .bind(&id_str)
                .bind(eid.to_string())
                .bind(&linked_at_str)
                .execute(&mut *tx)
                .await?;
            }

            let audit = AuditEntry::new(
                actor,
                "alert_created",
                "alert",
                Some(id_str),
                serde_json::json!({
                    "fingerprint": candidate.fingerprint,
                    "rule_id": rule_id_str,
                    "event_count": candidate.additional_observation_count,
                }),
            );
            AuditLogRepository::insert_entry_executor(&mut *tx, &audit).await?;

            tx.commit().await.map_err(StorageError::Database)?;
            info!(alert_id = %new_id, "Created new active security alert from candidate");

            Ok(CorrelationOutcome::Created(new_id))
        }
    }

    /// Queries alerts matching the bounded filter criteria.
    pub async fn query_alerts(
        &self,
        filter: &AlertQueryFilter,
    ) -> Result<Vec<PersistedAlert>, StorageError> {
        let limit = if filter.limit == 0 {
            DEFAULT_ALERT_QUERY_LIMIT
        } else {
            filter.limit.clamp(1, MAX_ALERT_QUERY_LIMIT)
        };

        let mut sql = String::from(
            r"
            SELECT id, rule_id, rule_version, severity, title, description,
                   first_seen, last_seen, created_at, updated_at, status, event_count, fingerprint
            FROM alerts
            WHERE 1=1
            ",
        );

        let mut binds: Vec<String> = Vec::new();

        if let Some(status) = filter.status {
            sql.push_str(" AND status = ?");
            binds.push(status_to_str(status).to_string());
        }

        if let Some(rule_id) = &filter.rule_id {
            sql.push_str(" AND rule_id = ?");
            binds.push(rule_id.clone());
        }

        if let Some(sev) = filter.severity {
            sql.push_str(" AND severity = ?");
            binds.push(severity_to_str(sev).to_string());
        }

        if let Some(start) = filter.start_time {
            sql.push_str(" AND created_at >= ?");
            binds.push(start.to_rfc3339());
        }

        if let Some(end) = filter.end_time {
            sql.push_str(" AND created_at <= ?");
            binds.push(end.to_rfc3339());
        }

        sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        let mut query = sqlx::query(&sql);
        for bind in binds {
            query = query.bind(bind);
        }
        query = query.bind(limit as i64).bind(filter.offset as i64);

        let rows = query.fetch_all(&self.pool).await?;
        let mut alerts = Vec::with_capacity(rows.len());

        for row in rows {
            let id_str: String = row.try_get("id")?;
            let aid =
                AlertId::from_uuid(Uuid::parse_str(&id_str).map_err(|e| {
                    StorageError::InvalidParameter(format!("invalid alert uuid: {e}"))
                })?);
            let evidence_ids = self.get_alert_evidence(aid).await?;
            let alert = map_alert_row(&row, evidence_ids)?;
            alerts.push(alert);
        }

        Ok(alerts)
    }

    /// Transitions an alert from `Open` to `Acknowledged` with audit logging.
    ///
    /// # Errors
    /// Returns [`StorageError::RecordNotFound`] if alert does not exist, or
    /// [`StorageError::InvalidStatusTransition`] if not in `Open` status.
    #[instrument(skip(self), fields(alert_id = %id, actor))]
    pub async fn acknowledge_alert(
        &self,
        id: AlertId,
        actor: &str,
        note: Option<&str>,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT status FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await?;

        let Some(row) = row else {
            return Err(StorageError::RecordNotFound(format!("alert {id}")));
        };

        let current_status_str: String = row.try_get("status")?;
        let current_status = str_to_status(&current_status_str)?;

        if current_status != AlertStatus::Open {
            return Err(StorageError::InvalidStatusTransition {
                from: current_status,
                to: AlertStatus::Acknowledged,
            });
        }

        let now = Utc::now();
        sqlx::query("UPDATE alerts SET status = 'acknowledged', updated_at = ? WHERE id = ?")
            .bind(now.to_rfc3339())
            .bind(&id_str)
            .execute(&mut *tx)
            .await?;

        let audit = AuditEntry::new(
            actor,
            "alert_acknowledged",
            "alert",
            Some(id_str),
            serde_json::json!({
                "note": note,
                "previous_status": current_status_str,
            }),
        );
        AuditLogRepository::insert_entry_executor(&mut *tx, &audit).await?;

        tx.commit().await.map_err(StorageError::Database)?;
        info!(alert_id = %id, "Alert transitioned to Acknowledged");
        Ok(())
    }

    /// Transitions an alert from `Open` or `Acknowledged` to `Resolved` with audit logging.
    ///
    /// # Errors
    /// Returns [`StorageError::RecordNotFound`] if alert does not exist, or
    /// [`StorageError::InvalidStatusTransition`] if already resolved.
    #[instrument(skip(self), fields(alert_id = %id, actor))]
    pub async fn resolve_alert(
        &self,
        id: AlertId,
        actor: &str,
        note: Option<&str>,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT status FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await?;

        let Some(row) = row else {
            return Err(StorageError::RecordNotFound(format!("alert {id}")));
        };

        let current_status_str: String = row.try_get("status")?;
        let current_status = str_to_status(&current_status_str)?;

        if current_status == AlertStatus::Resolved {
            return Err(StorageError::InvalidStatusTransition {
                from: AlertStatus::Resolved,
                to: AlertStatus::Resolved,
            });
        }

        let now = Utc::now();
        sqlx::query("UPDATE alerts SET status = 'resolved', updated_at = ? WHERE id = ?")
            .bind(now.to_rfc3339())
            .bind(&id_str)
            .execute(&mut *tx)
            .await?;

        let audit = AuditEntry::new(
            actor,
            "alert_resolved",
            "alert",
            Some(id_str),
            serde_json::json!({
                "note": note,
                "previous_status": current_status_str,
            }),
        );
        AuditLogRepository::insert_entry_executor(&mut *tx, &audit).await?;

        tx.commit().await.map_err(StorageError::Database)?;
        info!(alert_id = %id, "Alert transitioned to Resolved");
        Ok(())
    }

    /// Links an event to an alert as evidence.
    pub async fn link_event_to_alert(
        &self,
        alert_id: AlertId,
        event_id: EventId,
    ) -> Result<(), StorageError> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r"
            INSERT OR IGNORE INTO alert_events (alert_id, event_id, linked_at)
            VALUES (?, ?, ?)
            ",
        )
        .bind(alert_id.to_string())
        .bind(event_id.to_string())
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Links a slice of event IDs to an alert in a transaction.
    pub async fn link_events_to_alert(
        &self,
        alert_id: AlertId,
        event_ids: &[EventId],
    ) -> Result<usize, StorageError> {
        if event_ids.is_empty() {
            return Ok(0);
        }
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;
        let alert_id_str = alert_id.to_string();
        let now_str = Utc::now().to_rfc3339();
        let mut count = 0;

        for &eid in event_ids {
            let res = sqlx::query(
                r"
                INSERT OR IGNORE INTO alert_events (alert_id, event_id, linked_at)
                VALUES (?, ?, ?)
                ",
            )
            .bind(&alert_id_str)
            .bind(eid.to_string())
            .bind(&now_str)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() > 0 {
                count += 1;
            }
        }

        tx.commit().await.map_err(StorageError::Database)?;
        Ok(count)
    }

    /// Retrieves all supporting evidence event IDs linked to a specific alert.
    pub async fn get_alert_evidence(
        &self,
        alert_id: AlertId,
    ) -> Result<Vec<EventId>, StorageError> {
        let rows = sqlx::query(
            r"
            SELECT event_id
            FROM alert_events
            WHERE alert_id = ?
            ORDER BY linked_at ASC
            ",
        )
        .bind(alert_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut ids = Vec::with_capacity(rows.len());
        for row in rows {
            let eid_str: String = row.try_get("event_id")?;
            let uuid = Uuid::parse_str(&eid_str).map_err(|e| {
                StorageError::InvalidParameter(format!("invalid evidence event uuid: {e}"))
            })?;
            ids.push(EventId::from_uuid(uuid));
        }

        Ok(ids)
    }

    /// Returns the total count of alerts stored in the database.
    pub async fn count_alerts(&self) -> Result<usize, StorageError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alerts")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.max(0) as usize)
    }
}

/// Helper converting [`AlertSeverity`] to its canonical database representation.
#[must_use]
pub const fn severity_to_str(sev: AlertSeverity) -> &'static str {
    match sev {
        AlertSeverity::Informational => "informational",
        AlertSeverity::Low => "low",
        AlertSeverity::Medium => "medium",
        AlertSeverity::High => "high",
        AlertSeverity::Critical => "critical",
    }
}

/// Helper parsing database severity string into [`AlertSeverity`].
pub fn str_to_severity(s: &str) -> Result<AlertSeverity, StorageError> {
    match s.to_lowercase().as_str() {
        "informational" => Ok(AlertSeverity::Informational),
        "low" => Ok(AlertSeverity::Low),
        "medium" => Ok(AlertSeverity::Medium),
        "high" => Ok(AlertSeverity::High),
        "critical" => Ok(AlertSeverity::Critical),
        other => Err(StorageError::InvalidParameter(format!(
            "unknown alert severity '{other}'"
        ))),
    }
}

/// Helper converting [`AlertStatus`] to database string.
#[must_use]
pub const fn status_to_str(st: AlertStatus) -> &'static str {
    match st {
        AlertStatus::Open => "open",
        AlertStatus::Acknowledged => "acknowledged",
        AlertStatus::Resolved => "resolved",
    }
}

/// Helper parsing database status string into [`AlertStatus`].
pub fn str_to_status(s: &str) -> Result<AlertStatus, StorageError> {
    match s.to_lowercase().as_str() {
        "open" => Ok(AlertStatus::Open),
        "acknowledged" => Ok(AlertStatus::Acknowledged),
        "resolved" => Ok(AlertStatus::Resolved),
        other => Err(StorageError::InvalidParameter(format!(
            "unknown alert status '{other}'"
        ))),
    }
}

/// Maps a database row into a [`PersistedAlert`].
fn map_alert_row(
    row: &sqlx::sqlite::SqliteRow,
    evidence_event_ids: Vec<EventId>,
) -> Result<PersistedAlert, StorageError> {
    let id_str: String = row.try_get("id")?;
    let id = AlertId::from_uuid(
        Uuid::parse_str(&id_str)
            .map_err(|e| StorageError::InvalidParameter(format!("invalid alert id: {e}")))?,
    );

    let rule_id_str: String = row.try_get("rule_id")?;
    let rule_id = RuleId::new(rule_id_str).map_err(StorageError::Domain)?;

    let rule_version: String = row.try_get("rule_version")?;
    let severity_str: String = row.try_get("severity")?;
    let severity = str_to_severity(&severity_str)?;

    let title: String = row.try_get("title")?;
    let description: String = row.try_get("description")?;

    let first_seen_str: String = row.try_get("first_seen")?;
    let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
        .map_err(|e| StorageError::InvalidParameter(format!("invalid first_seen: {e}")))?
        .with_timezone(&Utc);

    let last_seen_str: String = row.try_get("last_seen")?;
    let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
        .map_err(|e| StorageError::InvalidParameter(format!("invalid last_seen: {e}")))?
        .with_timezone(&Utc);

    let created_at_str: String = row.try_get("created_at")?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| StorageError::InvalidParameter(format!("invalid created_at: {e}")))?
        .with_timezone(&Utc);

    let updated_at_str: String = row.try_get("updated_at")?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map_err(|e| StorageError::InvalidParameter(format!("invalid updated_at: {e}")))?
        .with_timezone(&Utc);

    let status_str: String = row.try_get("status")?;
    let status = str_to_status(&status_str)?;

    let event_count: i64 = row.try_get("event_count")?;
    let fingerprint: String = row.try_get("fingerprint")?;

    Ok(PersistedAlert {
        id,
        rule_id,
        rule_version,
        severity,
        title,
        description,
        first_seen,
        last_seen,
        created_at,
        updated_at,
        status,
        event_count: event_count.max(0) as usize,
        fingerprint,
        evidence_event_ids,
    })
}
