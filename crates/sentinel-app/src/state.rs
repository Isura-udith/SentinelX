//! Application state management, telemetry background scheduler, and settings persistence.

use crate::errors::AppError;
use crate::events::{
    AlertDetectedPayload, EVENT_ALERT_DETECTED, EVENT_TELEMETRY_CYCLE, TelemetryCyclePayload,
};
use crate::pipeline::PipelineCoordinator;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{ConnectionBurstConfig, ConnectionBurstRule, PortScanRule};
use sentinel_storage::rules::RuleRepository;
use sentinel_storage::{
    AlertRepository, AuditEntry, AuditLogRepository, Database, EventRepository, RetentionManager,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

/// Persistent application configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Active UI theme ("dark").
    pub theme: String,
    /// Frontend polling / refresh interval in seconds.
    pub refresh_interval_secs: u32,
    /// Default number of items per page in event and alert tables.
    pub event_table_page_size: usize,
    /// Absolute filesystem path to the SQLite database file.
    pub database_path: String,
    /// Number of days to retain telemetry events before purging.
    pub event_retention_days: u32,
    /// Number of days to retain audit records.
    pub audit_retention_days: u32,
    /// Interval between background telemetry snapshots in milliseconds.
    pub telemetry_polling_interval_ms: u64,
    /// Logging verbosity level ("info", "debug", "warn").
    pub log_verbosity: String,
    /// Whether synthetic demonstration telemetry is active.
    pub is_demo_mode: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        let db_path = default_database_path();
        Self {
            theme: "dark".to_string(),
            refresh_interval_secs: 5,
            event_table_page_size: 50,
            database_path: db_path.to_string_lossy().to_string(),
            event_retention_days: 30,
            audit_retention_days: 90,
            telemetry_polling_interval_ms: 1000,
            log_verbosity: "info".to_string(),
            is_demo_mode: !cfg!(target_os = "windows"),
        }
    }
}

/// Returns the platform-appropriate default database path in LocalAppData.
pub fn default_database_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local_app_data)
            .join("SentinelX")
            .join("sentinelx.db")
    } else {
        PathBuf::from("data").join("sentinelx.db")
    }
}

/// Returns the configuration file location.
pub fn settings_file_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local_app_data)
            .join("SentinelX")
            .join("settings.json")
    } else {
        PathBuf::from("data").join("settings.json")
    }
}

/// Operational telemetry control and diagnostics state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryControlState {
    /// Whether background polling is currently active.
    pub is_running: bool,
    /// Telemetry collector mode ("live_windows_tcp" or "mock").
    pub mode: String,
    /// Configured polling interval in milliseconds.
    pub polling_interval_ms: u64,
    /// Timestamp of most recent collection attempt.
    pub last_attempt: Option<DateTime<Utc>>,
    /// Timestamp of most recent successful collection.
    pub last_success: Option<DateTime<Utc>>,
    /// Most recent collector error message if degraded.
    pub last_error: Option<String>,
    /// Number of consecutive collection failures.
    pub consecutive_failures: u32,
    /// Total number of collection cycles attempted.
    pub cycle_counter: u64,
}

/// Managed global state accessible by Tauri command handlers.
pub struct AppState {
    /// Database instance.
    pub database: Database,
    /// Event repository.
    pub event_repo: EventRepository,
    /// Alert repository.
    pub alert_repo: AlertRepository,
    /// Audit log repository.
    pub audit_repo: AuditLogRepository,
    /// Detection rules repository.
    pub rule_repo: RuleRepository,
    /// Retention manager.
    pub retention_mgr: RetentionManager,
    /// Pipeline coordinator orchestrating collection, ingestion, and detection.
    pub coordinator: Arc<Mutex<PipelineCoordinator>>,
    /// Telemetry loop operational control state.
    pub telemetry_control: Arc<Mutex<TelemetryControlState>>,
    /// Application settings.
    pub settings: Arc<Mutex<AppSettings>>,
    /// Graceful shutdown flag.
    pub shutdown_flag: Arc<AtomicBool>,
    /// Optional Tauri application handle for emitting events.
    pub app_handle: RwLock<Option<AppHandle>>,
}

impl AppState {
    /// Initializes application state, ensures database migrations, seeds default rules,
    /// and prepares background telemetry coordination.
    pub async fn new(
        database: Database,
        coordinator: PipelineCoordinator,
        settings: AppSettings,
    ) -> Result<Arc<Self>, AppError> {
        let pool = database.pool().clone();
        let rule_repo = RuleRepository::new(pool.clone());
        rule_repo.seed_default_rules().await?;

        let mode = if settings.is_demo_mode {
            "mock".to_string()
        } else {
            "live_windows_tcp".to_string()
        };

        let control = TelemetryControlState {
            is_running: true,
            mode,
            polling_interval_ms: settings.telemetry_polling_interval_ms,
            last_attempt: None,
            last_success: None,
            last_error: None,
            consecutive_failures: 0,
            cycle_counter: 0,
        };

        let state = Arc::new(Self {
            event_repo: EventRepository::new(pool.clone()),
            alert_repo: AlertRepository::new(pool.clone()),
            audit_repo: AuditLogRepository::new(pool.clone()),
            rule_repo,
            retention_mgr: RetentionManager::new(pool),
            database,
            coordinator: Arc::new(Mutex::new(coordinator)),
            telemetry_control: Arc::new(Mutex::new(control)),
            settings: Arc::new(Mutex::new(settings)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            app_handle: RwLock::new(None),
        });

        // Spawn background telemetry polling loop
        Self::spawn_telemetry_loop(Arc::clone(&state));

        Ok(state)
    }

    /// Sets the active Tauri application handle for IPC event emission.
    pub async fn set_app_handle(&self, handle: AppHandle) {
        let mut writer = self.app_handle.write().await;
        *writer = Some(handle);
    }

    /// Saves updated settings to disk and updates in-memory state.
    pub async fn save_settings(
        &self,
        new_settings: AppSettings,
        actor: &str,
    ) -> Result<(), AppError> {
        let path = settings_file_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let json = serde_json::to_string_pretty(&new_settings)
            .map_err(|e| AppError::Internal(format!("Failed to serialize settings: {e}")))?;
        std::fs::write(&path, json)
            .map_err(|e| AppError::Internal(format!("Failed to write settings file: {e}")))?;

        // Update telemetry control if polling interval changed
        {
            let mut ctrl = self.telemetry_control.lock().await;
            ctrl.polling_interval_ms = new_settings.telemetry_polling_interval_ms;
        }

        // Record audit entry
        let audit = AuditEntry::new(
            actor,
            "settings_updated",
            "settings",
            Some("application_settings".to_string()),
            serde_json::json!({
                "refresh_interval_secs": new_settings.refresh_interval_secs,
                "event_retention_days": new_settings.event_retention_days,
                "audit_retention_days": new_settings.audit_retention_days,
                "telemetry_polling_interval_ms": new_settings.telemetry_polling_interval_ms,
                "is_demo_mode": new_settings.is_demo_mode,
            }),
        );
        self.audit_repo.insert_entry(&audit).await?;

        let mut lock = self.settings.lock().await;
        *lock = new_settings;

        Ok(())
    }

    /// Rebuilds the detection engine from current rule configurations and updates the coordinator.
    pub async fn reload_detection_engine(&self) -> Result<(), AppError> {
        let rules = self.rule_repo.list_rules().await?;

        let mut net001_cfg = DetectionConfig::default();
        let mut net001_enabled = true;

        let mut net002_cfg = ConnectionBurstConfig::default();
        let mut net002_enabled = true;

        for rule in &rules {
            if rule.rule_id == "NET-001" {
                net001_enabled = rule.enabled;
                if let Some(threshold) = rule
                    .config_json
                    .get("distinct_port_threshold")
                    .and_then(|v| v.as_u64())
                {
                    net001_cfg.distinct_port_threshold = threshold as u16;
                }
                if let Some(window) = rule
                    .config_json
                    .get("window_duration_secs")
                    .and_then(|v| v.as_i64())
                {
                    net001_cfg.window_duration = ChronoDuration::seconds(window);
                }
                if let Some(cooldown) = rule
                    .config_json
                    .get("cooldown_secs")
                    .and_then(|v| v.as_i64())
                {
                    net001_cfg.alert_cooldown = Some(ChronoDuration::seconds(cooldown));
                }
                if let Some(max_ev) = rule
                    .config_json
                    .get("max_evidence_ids")
                    .and_then(|v| v.as_u64())
                {
                    net001_cfg.max_evidence_ids_per_alert = max_ev as usize;
                }
            } else if rule.rule_id == "NET-002" {
                net002_enabled = rule.enabled;
                if let Some(threshold) = rule
                    .config_json
                    .get("observation_threshold")
                    .and_then(|v| v.as_u64())
                {
                    net002_cfg.observation_threshold = threshold as u32;
                }
                if let Some(window) = rule
                    .config_json
                    .get("window_duration_secs")
                    .and_then(|v| v.as_i64())
                {
                    net002_cfg.window_duration = ChronoDuration::seconds(window);
                }
                if let Some(cooldown) = rule
                    .config_json
                    .get("cooldown_secs")
                    .and_then(|v| v.as_i64())
                {
                    net002_cfg.alert_cooldown = Some(ChronoDuration::seconds(cooldown));
                }
                if let Some(max_ev) = rule
                    .config_json
                    .get("max_evidence_ids")
                    .and_then(|v| v.as_u64())
                {
                    net002_cfg.max_evidence_ids_per_alert = max_ev as usize;
                }
            }
        }

        let mut engine = DetectionEngine::new(net001_cfg.clone())
            .map_err(|e| AppError::Detection(e.to_string()))?;

        if net001_enabled {
            let port_scan =
                PortScanRule::new(net001_cfg).map_err(|e| AppError::Detection(e.to_string()))?;
            engine = engine.with_rule(Box::new(port_scan));
        }

        if net002_enabled {
            let burst_rule = ConnectionBurstRule::new(net002_cfg)
                .map_err(|e| AppError::Detection(e.to_string()))?;
            engine = engine.with_rule(Box::new(burst_rule));
        }

        let mut coord = self.coordinator.lock().await;
        coord.update_engine(engine);

        info!("Detection engine successfully reloaded with updated rule configurations");
        Ok(())
    }

    /// Spawns the autonomous background telemetry collection and detection loop.
    fn spawn_telemetry_loop(state: Arc<Self>) {
        tokio::spawn(async move {
            info!("Starting background telemetry scheduler task");

            loop {
                if state.shutdown_flag.load(Ordering::Relaxed) {
                    info!("Telemetry scheduler received shutdown signal; terminating");
                    break;
                }

                let (is_running, polling_interval_ms) = {
                    let ctrl = state.telemetry_control.lock().await;
                    (ctrl.is_running, ctrl.polling_interval_ms)
                };

                if is_running {
                    let now = Utc::now();
                    {
                        let mut ctrl = state.telemetry_control.lock().await;
                        ctrl.last_attempt = Some(now);
                        ctrl.cycle_counter = ctrl.cycle_counter.saturating_add(1);
                    }

                    let start_instant = Instant::now();
                    let cycle_result = {
                        let mut coord = state.coordinator.lock().await;
                        coord.process_cycle().await
                    };
                    let duration = start_instant.elapsed();
                    let duration_ms = duration.as_millis() as u64;

                    match cycle_result {
                        Ok(alerts) => {
                            let (raw_recs, ingested_evts) = {
                                let coord = state.coordinator.lock().await;
                                (
                                    coord.collection_stats().raw_records_observed as usize,
                                    coord.collection_stats().normalized_events_produced as usize,
                                )
                            };

                            let cycle_num = {
                                let mut ctrl = state.telemetry_control.lock().await;
                                ctrl.last_success = Some(Utc::now());
                                ctrl.last_error = None;
                                ctrl.consecutive_failures = 0;
                                ctrl.cycle_counter
                            };

                            // Emit telemetry cycle completed event to frontend
                            if let Some(ref handle) = *state.app_handle.read().await {
                                let payload = TelemetryCyclePayload {
                                    cycle: cycle_num,
                                    raw_records: raw_recs,
                                    events_ingested: ingested_evts,
                                    alerts_emitted: alerts.len(),
                                    duration_ms,
                                    timestamp: Utc::now(),
                                };
                                let _ = handle.emit(EVENT_TELEMETRY_CYCLE, payload);

                                for alert in alerts {
                                    let alert_payload = AlertDetectedPayload {
                                        alert_id: alert.id.to_string(),
                                        rule_id: alert.rule_id.to_string(),
                                        severity: alert.severity.to_string().to_lowercase(),
                                        title: alert.title,
                                        timestamp: alert.first_observed_at,
                                    };
                                    let _ = handle.emit(EVENT_ALERT_DETECTED, alert_payload);
                                }
                            }
                        }
                        Err(err) => {
                            let err_msg = err.to_string();
                            warn!(error = %err_msg, "Telemetry cycle failure");
                            let mut ctrl = state.telemetry_control.lock().await;
                            ctrl.last_error = Some(err_msg);
                            ctrl.consecutive_failures = ctrl.consecutive_failures.saturating_add(1);
                        }
                    }
                }

                let interval_duration =
                    Duration::from_millis(polling_interval_ms.clamp(100, 3600_000));
                tokio::time::sleep(interval_duration).await;
            }
        });
    }
}
