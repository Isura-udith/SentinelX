//! Detection rule metadata and configuration persistence in SQLite.

use crate::audit::{AuditEntry, AuditLogRepository};
use crate::error::StorageError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tracing::{info, instrument};

/// Persisted rule record in `detection_rules` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRule {
    /// Unique rule identifier (e.g. "NET-001", "NET-002").
    pub rule_id: String,
    /// Display name of the detection rule.
    pub name: String,
    /// Technical description.
    pub description: String,
    /// Whether the rule is actively evaluated.
    pub enabled: bool,
    /// Software or rule logic version.
    pub rule_version: String,
    /// Registration timestamp in UTC.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp in UTC.
    pub updated_at: DateTime<Utc>,
    /// Additional JSON configuration parameters (thresholds, windows, cooldowns).
    pub config_json: serde_json::Value,
}

/// Repository managing detection rule registration and configuration in SQLite.
#[derive(Debug, Clone)]
pub struct RuleRepository {
    pool: SqlitePool,
}

impl RuleRepository {
    /// Creates a new `RuleRepository`.
    #[must_use]
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Fetches a rule by its identifier.
    #[instrument(skip(self))]
    pub async fn get_rule(&self, rule_id: &str) -> Result<Option<PersistedRule>, StorageError> {
        let row = sqlx::query(
            r"
            SELECT rule_id, name, description, enabled, rule_version, created_at, updated_at, config_json
            FROM detection_rules
            WHERE rule_id = ?
            ",
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| Self::map_rule_row(&r)).transpose()
    }

    /// Lists all registered detection rules.
    #[instrument(skip(self))]
    pub async fn list_rules(&self) -> Result<Vec<PersistedRule>, StorageError> {
        let rows = sqlx::query(
            r"
            SELECT rule_id, name, description, enabled, rule_version, created_at, updated_at, config_json
            FROM detection_rules
            ORDER BY rule_id ASC
            ",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut rules = Vec::with_capacity(rows.len());
        for row in rows {
            rules.push(Self::map_rule_row(&row)?);
        }
        Ok(rules)
    }

    /// Upserts a detection rule and creates an audit log entry.
    #[instrument(skip(self, rule))]
    pub async fn upsert_rule(&self, rule: &PersistedRule, actor: &str) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;

        let created_at_str = rule.created_at.to_rfc3339();
        let updated_at_str = rule.updated_at.to_rfc3339();
        let config_str = serde_json::to_string(&rule.config_json)?;

        sqlx::query(
            r"
            INSERT INTO detection_rules (
                rule_id, name, description, enabled, rule_version, created_at, updated_at, config_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                enabled = excluded.enabled,
                rule_version = excluded.rule_version,
                updated_at = excluded.updated_at,
                config_json = excluded.config_json
            ",
        )
        .bind(&rule.rule_id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(i64::from(rule.enabled))
        .bind(&rule.rule_version)
        .bind(created_at_str)
        .bind(updated_at_str)
        .bind(config_str)
        .execute(&mut *tx)
        .await?;

        let audit = AuditEntry::new(
            actor,
            "rule_updated",
            "rule",
            Some(rule.rule_id.clone()),
            serde_json::json!({
                "enabled": rule.enabled,
                "rule_version": rule.rule_version,
                "config": rule.config_json,
            }),
        );
        AuditLogRepository::insert_entry_executor(&mut *tx, &audit).await?;

        tx.commit().await.map_err(StorageError::Database)?;
        info!(rule_id = %rule.rule_id, enabled = rule.enabled, "Detection rule persisted");
        Ok(())
    }

    /// Seeds default rules (NET-001 and NET-002) if not already present.
    pub async fn seed_default_rules(&self) -> Result<(), StorageError> {
        let now = Utc::now();

        if self.get_rule("NET-001").await?.is_none() {
            let net001 = PersistedRule {
                rule_id: "NET-001".to_string(),
                name: "Horizontal & Vertical Port Scan Detection".to_string(),
                description: "Detects distinct destination port sweeps from a single source address within an event-time rolling window.".to_string(),
                enabled: true,
                rule_version: "1.0.0".to_string(),
                created_at: now,
                updated_at: now,
                config_json: serde_json::json!({
                    "distinct_port_threshold": 10,
                    "window_duration_secs": 60,
                    "cooldown_secs": 300,
                    "max_evidence_ids": 20
                }),
            };
            self.upsert_rule(&net001, "system_seed").await?;
        }

        if self.get_rule("NET-002").await?.is_none() {
            let net002 = PersistedRule {
                rule_id: "NET-002".to_string(),
                name: "High Connection-Volume Anomaly Detection".to_string(),
                description: "Identifies a single source address producing an unusually dense volume of connection observations within a rolling window.".to_string(),
                enabled: true,
                rule_version: "1.0.0".to_string(),
                created_at: now,
                updated_at: now,
                config_json: serde_json::json!({
                    "observation_threshold": 20,
                    "window_duration_secs": 60,
                    "cooldown_secs": 300,
                    "max_evidence_ids": 50
                }),
            };
            self.upsert_rule(&net002, "system_seed").await?;
        }

        Ok(())
    }

    fn map_rule_row(row: &sqlx::sqlite::SqliteRow) -> Result<PersistedRule, StorageError> {
        let rule_id: String = row.try_get("rule_id")?;
        let name: String = row.try_get("name")?;
        let description: String = row.try_get("description")?;
        let enabled_num: i64 = row.try_get("enabled")?;
        let enabled = enabled_num != 0;
        let rule_version: String = row.try_get("rule_version")?;

        let created_at_str: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| StorageError::InvalidParameter(format!("invalid created_at: {e}")))?
            .with_timezone(&Utc);

        let updated_at_str: String = row.try_get("updated_at")?;
        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| StorageError::InvalidParameter(format!("invalid updated_at: {e}")))?
            .with_timezone(&Utc);

        let config_str: String = row
            .try_get("config_json")
            .unwrap_or_else(|_| "{}".to_string());
        let config_json: serde_json::Value = serde_json::from_str(&config_str)?;

        Ok(PersistedRule {
            rule_id,
            name,
            description,
            enabled,
            rule_version,
            created_at,
            updated_at,
            config_json,
        })
    }
}
