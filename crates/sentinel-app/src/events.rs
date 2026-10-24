//! Tauri IPC event payloads for reactive frontend updates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Event name constants for Tauri IPC event bus.
pub const EVENT_TELEMETRY_CYCLE: &str = "telemetry-cycle";
pub const EVENT_ALERT_DETECTED: &str = "alert-detected";
pub const EVENT_ALERT_STATUS_CHANGED: &str = "alert-status-changed";
pub const EVENT_COLLECTOR_STATE_CHANGED: &str = "collector-state-changed";

/// Payload emitted when a telemetry collection & detection cycle completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryCyclePayload {
    /// Incremental cycle number.
    pub cycle: u64,
    /// Raw records observed in the snapshot.
    pub raw_records: usize,
    /// Normalized events committed to storage.
    pub events_ingested: usize,
    /// New alerts emitted in this cycle.
    pub alerts_emitted: usize,
    /// Duration of cycle in milliseconds.
    pub duration_ms: u64,
    /// UTC timestamp of cycle completion.
    pub timestamp: DateTime<Utc>,
}

/// Payload emitted when a security alert is triggered or updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDetectedPayload {
    /// Unique identifier of the alert.
    pub alert_id: String,
    /// Detection rule identifier (e.g. NET-001).
    pub rule_id: String,
    /// Severity level string ("informational", "low", "medium", "high", "critical").
    pub severity: String,
    /// Alert display title.
    pub title: String,
    /// Observation timestamp in UTC.
    pub timestamp: DateTime<Utc>,
}

/// Payload emitted when an alert is acknowledged or resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatusChangedPayload {
    /// Unique identifier of the modified alert.
    pub alert_id: String,
    /// New triage status ("open", "acknowledged", "resolved").
    pub new_status: String,
    /// UTC timestamp of modification.
    pub updated_at: DateTime<Utc>,
}

/// Payload emitted when collector operational state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStateChangedPayload {
    /// Whether the background collection loop is actively polling.
    pub is_running: bool,
    /// Active telemetry source mode.
    pub mode: String,
    /// Configured polling interval in milliseconds.
    pub polling_interval_ms: u64,
}
