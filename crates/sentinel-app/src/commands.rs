//! Strongly-typed Tauri commands exposing defensive backend operations to React.

use crate::errors::AppError;
use crate::events::{
    AlertStatusChangedPayload, CollectorStateChangedPayload, EVENT_ALERT_STATUS_CHANGED,
    EVENT_COLLECTOR_STATE_CHANGED,
};
use crate::state::{AppSettings, AppState};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_collector::windows_tcp::WindowsTcpCollector;
use sentinel_core::alert::{AlertId, AlertSeverity};
use sentinel_core::event::{EventId, NetworkProtocol, TelemetrySource};
use sentinel_storage::alerts::{str_to_severity, str_to_status};
use sentinel_storage::{
    AlertQueryFilter, AuditEntry, AuditQueryFilter, EventQueryFilter, PersistedAlert,
    PersistedEvent,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tauri::{Emitter, State};
use tracing::info;
use uuid::Uuid;

// ============================================================================
// DTOs & Response Models
// ============================================================================

/// System status response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatusDto {
    pub telemetry_running: bool,
    pub collector_mode: String,
    pub database_connected: bool,
    pub database_path: String,
    pub detection_engine_healthy: bool,
    pub last_collection_time: Option<DateTime<Utc>>,
    pub is_demo_mode: bool,
    pub app_version: String,
}

/// Alert severity distribution counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertSeverityDistributionDto {
    pub informational: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

/// Time-series observation activity bucket for dashboard chart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesBucketDto {
    pub timestamp: DateTime<Utc>,
    pub event_count: usize,
    pub alert_count: usize,
}

/// Dashboard summary response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummaryDto {
    pub total_events: usize,
    pub events_last_hour: usize,
    pub open_alerts: usize,
    pub high_and_critical_alerts: usize,
    pub high_critical_alerts: usize,
    pub successful_collections: u64,
    pub detection_status: String,
    pub detection_healthy: bool,
    pub severity_distribution: AlertSeverityDistributionDto,
    pub activity_time_series: Vec<TimeSeriesBucketDto>,
    pub recent_alerts: Vec<AlertDto>,
    pub recent_events: Vec<NetworkEventDto>,
    pub collector_name: String,
    pub collector_status: TelemetryStatusDto,
    pub collection_duration_ms: u64,
}

/// Normalized network event response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventDto {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub telemetry_source: String,
    pub protocol: String,
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub process_id: Option<u32>,
    pub socket_state: String,
    pub metadata: BTreeMap<String, String>,
    pub ingested_at: DateTime<Utc>,
}

impl From<&PersistedEvent> for NetworkEventDto {
    fn from(pe: &PersistedEvent) -> Self {
        let meta_map: BTreeMap<String, String> = pe
            .event
            .metadata
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let socket_state = pe
            .event
            .metadata
            .get("tcp_state")
            .or_else(|| pe.event.metadata.get("socket_state"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "ESTABLISHED".to_string());

        Self {
            id: pe.event.id.to_string(),
            timestamp: pe.event.timestamp,
            source: pe.event.source.to_string(),
            telemetry_source: pe.event.source.to_string(),
            protocol: pe.event.protocol.to_string(),
            source_ip: pe.event.source_ip.as_ref().map(ToString::to_string),
            source_port: pe.event.source_port,
            destination_ip: pe.event.destination_ip.as_ref().map(ToString::to_string),
            destination_port: pe.event.destination_port,
            process_id: pe.event.process_id.map(|p| p.as_u32()),
            socket_state,
            metadata: meta_map,
            ingested_at: pe.ingested_at,
        }
    }
}

/// Security alert response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDto {
    pub id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: String,
    pub event_count: usize,
    pub fingerprint: String,
    pub evidence_count: usize,
    pub evidence_event_count: usize,
    pub source_ip: Option<String>,
}

impl From<&PersistedAlert> for AlertDto {
    fn from(pa: &PersistedAlert) -> Self {
        let source_ip = pa.fingerprint.split_once(':').and_then(|(_, ip_part)| {
            if ip_part == "none" || ip_part.is_empty() {
                None
            } else {
                Some(ip_part.to_string())
            }
        });

        Self {
            id: pa.id.to_string(),
            rule_id: pa.rule_id.to_string(),
            rule_version: pa.rule_version.clone(),
            severity: pa.severity.to_string().to_lowercase(),
            title: pa.title.clone(),
            description: pa.description.clone(),
            first_seen: pa.first_seen,
            last_seen: pa.last_seen,
            created_at: pa.created_at,
            updated_at: pa.updated_at,
            status: pa.status.to_string().to_lowercase(),
            event_count: pa.event_count,
            fingerprint: pa.fingerprint.clone(),
            evidence_count: pa.evidence_event_ids.len(),
            evidence_event_count: pa.evidence_event_ids.len(),
            source_ip,
        }
    }
}

/// Alert details with supporting evidence and associated audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDetailsDto {
    #[serde(flatten)]
    pub alert: AlertDto,
    pub evidence_event_ids: Vec<String>,
    pub associated_audit_history: Vec<AuditEntryDto>,
    pub evidence_events: Vec<NetworkEventDto>,
    pub total_evidence_count: usize,
    pub retained_evidence_count: usize,
    pub purged_evidence_count: usize,
    pub audit_history: Vec<AuditEntryDto>,
}

/// Supporting evidence response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvidenceResponseDto {
    pub events: Vec<NetworkEventDto>,
    pub total_evidence_ids: usize,
    pub retained_count: usize,
    pub purged_count: usize,
    pub is_expired: bool,
}

/// Detection rule metadata and configuration DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleDto {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub rule_version: String,
    pub threshold: u32,
    pub window_duration_secs: i64,
    pub cooldown_secs: Option<i64>,
    pub max_evidence_ids: usize,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Telemetry status DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryStatusDto {
    pub collector_type: String,
    pub collector_mode: String,
    pub is_running: bool,
    pub polling_interval_ms: u64,
    pub last_attempt: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub last_successful_collection: Option<DateTime<Utc>>,
    pub raw_records_observed: u64,
    pub normalized_events_produced: u64,
    pub skipped_records: u64,
    pub collection_failures: u64,
    pub recent_duration_ms: Option<f64>,
    pub average_duration_ms: f64,
    pub last_error: Option<String>,
    pub most_recent_error: Option<String>,
}

/// Audit log record response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryDto {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub details: serde_json::Value,
}

impl From<&AuditEntry> for AuditEntryDto {
    fn from(e: &AuditEntry) -> Self {
        Self {
            id: e.id.to_string(),
            timestamp: e.timestamp,
            actor: e.actor.clone(),
            action: e.action.clone(),
            target_type: e.target_type.clone(),
            target_id: e.target_id.clone(),
            details: e.details_json.clone(),
        }
    }
}

/// Generic bounded paginated wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub total_count: usize,
    pub limit: usize,
    pub offset: usize,
}

// ============================================================================
// Input Parameters
// ============================================================================

/// Query parameters for network events table.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventQueryParams {
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub source: Option<String>,
    pub search_text: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_desc: Option<bool>,
}

/// Query parameters for security alerts table.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AlertQueryParams {
    pub status: Option<String>,
    pub rule_id: Option<String>,
    pub severity: Option<String>,
    pub search_text: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Query parameters for audit history table.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditQueryParams {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Input model for updating a detection rule.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateDetectionRuleInput {
    pub rule_id: String,
    pub enabled: bool,
    pub threshold: u32,
    pub window_duration_secs: i64,
    pub cooldown_secs: Option<i64>,
    pub max_evidence_ids: usize,
}

/// Input model for updating application settings.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateApplicationSettingsInput {
    pub theme: Option<String>,
    pub refresh_interval_secs: Option<u32>,
    pub event_table_page_size: Option<usize>,
    pub event_retention_days: Option<u32>,
    pub audit_retention_days: Option<u32>,
    pub telemetry_polling_interval_ms: Option<u64>,
    pub log_verbosity: Option<String>,
    pub is_demo_mode: Option<bool>,
}

// ============================================================================
// Core Implementations & Tauri Handlers
// ============================================================================

pub async fn get_system_status_impl(state: &AppState) -> Result<SystemStatusDto, AppError> {
    let ctrl = state.telemetry_control.lock().await;
    let settings = state.settings.lock().await;

    Ok(SystemStatusDto {
        telemetry_running: ctrl.is_running,
        collector_mode: ctrl.mode.clone(),
        database_connected: true,
        database_path: settings.database_path.clone(),
        detection_engine_healthy: ctrl.last_error.is_none(),
        last_collection_time: ctrl.last_success,
        is_demo_mode: settings.is_demo_mode,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[tauri::command]
pub async fn get_system_status(
    state: State<'_, Arc<AppState>>,
) -> Result<SystemStatusDto, AppError> {
    get_system_status_impl(&state).await
}

pub async fn get_dashboard_summary_impl(
    state: &AppState,
    time_range: Option<String>,
) -> Result<DashboardSummaryDto, AppError> {
    let now = Utc::now();
    let range_duration = match time_range.as_deref() {
        Some("1h") => ChronoDuration::hours(1),
        Some("6h") => ChronoDuration::hours(6),
        Some("24h") | None => ChronoDuration::hours(24),
        Some("7d") => ChronoDuration::days(7),
        _ => ChronoDuration::hours(24),
    };
    let start_time = now - range_duration;

    let total_events = state.event_repo.count_events().await?;
    let hour_ago = now - ChronoDuration::hours(1);
    let events_last_hour = state.event_repo.count_events_since(hour_ago).await?;

    let open_alerts = state.alert_repo.count_open_alerts().await?;
    let high_and_critical_alerts = state.alert_repo.count_high_critical_alerts().await?;
    let sev_counts = state.alert_repo.count_by_severity().await?;

    let severity_distribution = AlertSeverityDistributionDto {
        informational: *sev_counts.get(&AlertSeverity::Informational).unwrap_or(&0),
        low: *sev_counts.get(&AlertSeverity::Low).unwrap_or(&0),
        medium: *sev_counts.get(&AlertSeverity::Medium).unwrap_or(&0),
        high: *sev_counts.get(&AlertSeverity::High).unwrap_or(&0),
        critical: *sev_counts.get(&AlertSeverity::Critical).unwrap_or(&0),
    };

    let bucket_count = 12;
    let step = range_duration / bucket_count;
    let mut activity_time_series = Vec::with_capacity(bucket_count as usize);

    for i in 0..bucket_count {
        let bucket_start = start_time + (step * i);
        let bucket_end = bucket_start + step;

        let ev_filter = EventQueryFilter::new().with_time_range(bucket_start, bucket_end);
        let ev_cnt = state
            .event_repo
            .count_matching_events(&ev_filter)
            .await
            .unwrap_or(0);

        let al_filter = AlertQueryFilter::new().with_time_range(bucket_start, bucket_end);
        let al_cnt = state
            .alert_repo
            .count_matching_alerts(&al_filter)
            .await
            .unwrap_or(0);

        activity_time_series.push(TimeSeriesBucketDto {
            timestamp: bucket_end,
            event_count: ev_cnt,
            alert_count: al_cnt,
        });
    }

    let recent_alerts_raw = state
        .alert_repo
        .query_alerts(&AlertQueryFilter::new().with_limit(5))
        .await?;
    let recent_alerts: Vec<AlertDto> = recent_alerts_raw.iter().map(AlertDto::from).collect();

    let recent_events_raw = state
        .event_repo
        .query_events(&EventQueryFilter::new().with_limit(5).with_sort_desc(true))
        .await?;
    let recent_events: Vec<NetworkEventDto> = recent_events_raw
        .iter()
        .map(NetworkEventDto::from)
        .collect();

    let (
        collector_name,
        collector_status_dto,
        duration_ms,
        collections_count,
        is_running,
        has_error,
    ) = {
        let ctrl = state.telemetry_control.lock().await;
        let coord = state.coordinator.lock().await;
        let stats = coord.collection_stats();

        let mode_name = if ctrl.mode == "mock" {
            "Deterministic Mock Telemetry Collector"
        } else {
            "Windows TCP Connection Snapshot Collector"
        };

        let collector_mode = if ctrl.mode == "mock" {
            "Deterministic Mock"
        } else {
            "Live Windows TCP Snapshot (GetExtendedTcpTable)"
        };

        let duration_f64 = stats.most_recent_duration.map(|d| d.as_secs_f64() * 1000.0);

        let status_dto = TelemetryStatusDto {
            collector_type: mode_name.to_string(),
            collector_mode: collector_mode.to_string(),
            is_running: ctrl.is_running,
            polling_interval_ms: ctrl.polling_interval_ms,
            last_attempt: ctrl.last_attempt,
            last_success: ctrl.last_success,
            last_successful_collection: ctrl.last_success,
            raw_records_observed: stats.raw_records_observed,
            normalized_events_produced: stats.normalized_events_produced,
            skipped_records: stats.records_skipped,
            collection_failures: stats.failed_cycles,
            recent_duration_ms: duration_f64,
            average_duration_ms: duration_f64.unwrap_or(0.0),
            last_error: ctrl.last_error.clone(),
            most_recent_error: ctrl.last_error.clone(),
        };

        (
            mode_name.to_string(),
            status_dto,
            stats
                .most_recent_duration
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            stats.successful_cycles,
            ctrl.is_running,
            ctrl.last_error.is_some(),
        )
    };

    let detection_status = if !is_running {
        "stopped".to_string()
    } else if has_error {
        "degraded".to_string()
    } else {
        "operational".to_string()
    };

    Ok(DashboardSummaryDto {
        total_events,
        events_last_hour,
        open_alerts,
        high_and_critical_alerts,
        high_critical_alerts: high_and_critical_alerts,
        successful_collections: collections_count,
        detection_status,
        detection_healthy: !has_error,
        severity_distribution,
        activity_time_series,
        recent_alerts,
        recent_events,
        collector_name,
        collector_status: collector_status_dto,
        collection_duration_ms: duration_ms,
    })
}

#[tauri::command]
pub async fn get_dashboard_summary(
    state: State<'_, Arc<AppState>>,
    time_range: Option<String>,
) -> Result<DashboardSummaryDto, AppError> {
    get_dashboard_summary_impl(&state, time_range).await
}

pub async fn query_network_events_impl(
    state: &AppState,
    params: EventQueryParams,
) -> Result<PaginatedResponse<NetworkEventDto>, AppError> {
    if let Some(ref s) = params.source_ip {
        if s.len() > 64 {
            return Err(AppError::Validation(
                "Source IP string must not exceed 64 characters".to_string(),
            ));
        }
    }

    if let Some(ref d) = params.destination_ip {
        if d.len() > 64 {
            return Err(AppError::Validation(
                "Destination IP string must not exceed 64 characters".to_string(),
            ));
        }
    }

    if let Some(ref t) = params.search_text {
        if t.len() > 256 {
            return Err(AppError::Validation(
                "Search text must not exceed 256 characters".to_string(),
            ));
        }
    }

    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0);
    if offset > 1_000_000 {
        return Err(AppError::Validation(
            "Query offset exceeds maximum limit of 1,000,000".to_string(),
        ));
    }

    let mut filter = EventQueryFilter::new()
        .with_limit(limit)
        .with_offset(offset);

    if let Some(src_str) = params.source_ip {
        if !src_str.trim().is_empty() {
            let ip = IpAddr::from_str(src_str.trim())
                .map_err(|e| AppError::Validation(format!("Invalid source IP address: {e}")))?;
            filter = filter.with_source_ip(ip);
        }
    }

    if let Some(dst_str) = params.destination_ip {
        if !dst_str.trim().is_empty() {
            let ip = IpAddr::from_str(dst_str.trim()).map_err(|e| {
                AppError::Validation(format!("Invalid destination IP address: {e}"))
            })?;
            filter = filter.with_destination_ip(ip);
        }
    }

    if let Some(port) = params.destination_port {
        if port == 0 {
            return Err(AppError::Validation(
                "Destination port must be between 1 and 65535".to_string(),
            ));
        }
        filter = filter.with_destination_port(port);
    }

    if let Some(proto_str) = params.protocol {
        if !proto_str.trim().is_empty() && proto_str != "all" {
            let proto = match proto_str.trim().to_uppercase().as_str() {
                "TCP" => NetworkProtocol::Tcp,
                "UDP" => NetworkProtocol::Udp,
                other => return Err(AppError::Validation(format!("Invalid protocol: {other}"))),
            };
            filter = filter.with_protocol(proto);
        }
    }

    if let Some(source_str) = params.source {
        if !source_str.trim().is_empty() && source_str != "all" {
            let src = match source_str.trim().to_lowercase().as_str() {
                "synthetic_simulator" | "synthetic" => TelemetrySource::SyntheticSimulator,
                "windows_tcp_snapshot" | "windows_tcp" => TelemetrySource::WindowsTcpSnapshot,
                "windows_event_telemetry" => TelemetrySource::WindowsEventTelemetry,
                "packet_metadata" => TelemetrySource::PacketMetadata,
                other => {
                    return Err(AppError::Validation(format!(
                        "Invalid telemetry source: {other}"
                    )));
                }
            };
            filter = filter.with_source(src);
        }
    }

    if let Some(txt) = params.search_text {
        if !txt.trim().is_empty() {
            filter = filter.with_search_text(txt.trim());
        }
    }

    if let (Some(start), Some(end)) = (params.start_time, params.end_time) {
        if start > end {
            return Err(AppError::Validation(
                "Start time cannot be after end time".to_string(),
            ));
        }
        filter = filter.with_time_range(start, end);
    }

    if let Some(sort_desc) = params.sort_desc {
        filter = filter.with_sort_desc(sort_desc);
    } else {
        filter = filter.with_sort_desc(true);
    }

    let total = state.event_repo.count_matching_events(&filter).await?;
    let raw_events = state.event_repo.query_events(&filter).await?;
    let items = raw_events.iter().map(NetworkEventDto::from).collect();

    Ok(PaginatedResponse {
        items,
        total,
        total_count: total,
        limit: filter.limit,
        offset: filter.offset,
    })
}

#[tauri::command]
pub async fn query_network_events(
    state: State<'_, Arc<AppState>>,
    params: EventQueryParams,
) -> Result<PaginatedResponse<NetworkEventDto>, AppError> {
    query_network_events_impl(&state, params).await
}

pub async fn get_network_event_details_impl(
    state: &AppState,
    event_id: String,
) -> Result<Option<NetworkEventDto>, AppError> {
    let uuid = Uuid::parse_str(event_id.trim())
        .map_err(|e| AppError::Validation(format!("Invalid event UUID: {e}")))?;
    let id = EventId::from_uuid(uuid);

    let raw = state.event_repo.get_event_by_id(id).await?;
    Ok(raw.as_ref().map(NetworkEventDto::from))
}

#[tauri::command]
pub async fn get_network_event_details(
    state: State<'_, Arc<AppState>>,
    event_id: String,
) -> Result<Option<NetworkEventDto>, AppError> {
    get_network_event_details_impl(&state, event_id).await
}

pub async fn query_security_alerts_impl(
    state: &AppState,
    params: AlertQueryParams,
) -> Result<PaginatedResponse<AlertDto>, AppError> {
    if let Some(ref t) = params.search_text {
        if t.len() > 256 {
            return Err(AppError::Validation(
                "Search text must not exceed 256 characters".to_string(),
            ));
        }
    }

    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0);
    if offset > 1_000_000 {
        return Err(AppError::Validation(
            "Query offset exceeds maximum limit of 1,000,000".to_string(),
        ));
    }

    let mut filter = AlertQueryFilter::new()
        .with_limit(limit)
        .with_offset(offset);

    if let Some(status_str) = params.status {
        if !status_str.trim().is_empty() && status_str != "all" {
            let status = str_to_status(status_str.trim())
                .map_err(|e| AppError::Validation(format!("Invalid alert status: {e}")))?;
            filter = filter.with_status(status);
        }
    }

    if let Some(rule_id_str) = params.rule_id {
        if !rule_id_str.trim().is_empty() && rule_id_str != "all" {
            filter = filter.with_rule_id(rule_id_str.trim());
        }
    }

    if let Some(sev_str) = params.severity {
        if !sev_str.trim().is_empty() && sev_str != "all" {
            let sev = str_to_severity(sev_str.trim())
                .map_err(|e| AppError::Validation(format!("Invalid alert severity: {e}")))?;
            filter = filter.with_severity(sev);
        }
    }

    if let Some(txt) = params.search_text {
        if !txt.trim().is_empty() {
            filter = filter.with_search_text(txt.trim());
        }
    }

    if let (Some(start), Some(end)) = (params.start_time, params.end_time) {
        if start > end {
            return Err(AppError::Validation(
                "Start time cannot be after end time".to_string(),
            ));
        }
        filter.start_time = Some(start);
        filter.end_time = Some(end);
    }

    let total = state.alert_repo.count_matching_alerts(&filter).await?;
    let raw_alerts = state.alert_repo.query_alerts(&filter).await?;
    let items = raw_alerts.iter().map(AlertDto::from).collect();

    Ok(PaginatedResponse {
        items,
        total,
        total_count: total,
        limit: filter.limit,
        offset: filter.offset,
    })
}

#[tauri::command]
pub async fn query_security_alerts(
    state: State<'_, Arc<AppState>>,
    params: AlertQueryParams,
) -> Result<PaginatedResponse<AlertDto>, AppError> {
    query_security_alerts_impl(&state, params).await
}

pub async fn get_security_alert_details_impl(
    state: &AppState,
    alert_id: String,
) -> Result<Option<AlertDetailsDto>, AppError> {
    let uuid = Uuid::parse_str(alert_id.trim())
        .map_err(|e| AppError::Validation(format!("Invalid alert UUID: {e}")))?;
    let aid = AlertId::from_uuid(uuid);

    let raw_alert = state.alert_repo.get_alert_by_id(aid).await?;
    let Some(alert) = raw_alert else {
        return Ok(None);
    };

    let total_evidence_count = alert.evidence_event_ids.len();
    let mut evidence_events = Vec::new();

    for &eid in &alert.evidence_event_ids {
        if let Some(pe) = state.event_repo.get_event_by_id(eid).await? {
            evidence_events.push(NetworkEventDto::from(&pe));
        }
    }

    let retained_evidence_count = evidence_events.len();
    let purged_evidence_count = total_evidence_count.saturating_sub(retained_evidence_count);

    let audit_filter = AuditQueryFilter::new()
        .with_target("alert", Some(alert.id.to_string()))
        .with_limit(100);
    let audit_raw = state.audit_repo.query_entries(&audit_filter).await?;
    let audit_history: Vec<AuditEntryDto> = audit_raw.iter().map(AuditEntryDto::from).collect();

    let evidence_event_ids = alert
        .evidence_event_ids
        .iter()
        .map(ToString::to_string)
        .collect();

    Ok(Some(AlertDetailsDto {
        alert: AlertDto::from(&alert),
        evidence_event_ids,
        associated_audit_history: audit_history.clone(),
        evidence_events,
        total_evidence_count,
        retained_evidence_count,
        purged_evidence_count,
        audit_history,
    }))
}

#[tauri::command]
pub async fn get_security_alert_details(
    state: State<'_, Arc<AppState>>,
    alert_id: String,
) -> Result<Option<AlertDetailsDto>, AppError> {
    get_security_alert_details_impl(&state, alert_id).await
}

pub async fn get_alert_evidence_impl(
    state: &AppState,
    alert_id: String,
) -> Result<Vec<NetworkEventDto>, AppError> {
    let uuid = Uuid::parse_str(alert_id.trim())
        .map_err(|e| AppError::Validation(format!("Invalid alert UUID: {e}")))?;
    let aid = AlertId::from_uuid(uuid);

    let evidence_ids = state.alert_repo.get_alert_evidence(aid).await?;
    let mut events = Vec::new();

    for &eid in &evidence_ids {
        if let Some(pe) = state.event_repo.get_event_by_id(eid).await? {
            events.push(NetworkEventDto::from(&pe));
        }
    }

    Ok(events)
}

#[tauri::command]
pub async fn get_alert_evidence(
    state: State<'_, Arc<AppState>>,
    alert_id: String,
) -> Result<Vec<NetworkEventDto>, AppError> {
    get_alert_evidence_impl(&state, alert_id).await
}

pub async fn acknowledge_alert_impl(
    state: &AppState,
    alert_id: String,
    note: Option<String>,
) -> Result<(), AppError> {
    if let Some(ref n) = note {
        if n.len() > 1024 {
            return Err(AppError::Validation(
                "Analyst note must not exceed 1024 characters".to_string(),
            ));
        }
    }

    let uuid = Uuid::parse_str(alert_id.trim())
        .map_err(|e| AppError::Validation(format!("Invalid alert UUID: {e}")))?;
    let aid = AlertId::from_uuid(uuid);

    state
        .alert_repo
        .acknowledge_alert(aid, "security_analyst", note.as_deref())
        .await?;

    info!(alert_id = %aid, "Alert acknowledged by analyst");

    if let Some(ref handle) = *state.app_handle.read().await {
        let _ = handle.emit(
            EVENT_ALERT_STATUS_CHANGED,
            AlertStatusChangedPayload {
                alert_id: aid.to_string(),
                new_status: "acknowledged".to_string(),
                updated_at: Utc::now(),
            },
        );
    }

    Ok(())
}

#[tauri::command]
pub async fn acknowledge_alert(
    state: State<'_, Arc<AppState>>,
    alert_id: String,
    note: Option<String>,
) -> Result<(), AppError> {
    acknowledge_alert_impl(&state, alert_id, note).await
}

pub async fn resolve_alert_impl(
    state: &AppState,
    alert_id: String,
    note: Option<String>,
) -> Result<(), AppError> {
    if let Some(ref n) = note {
        if n.len() > 1024 {
            return Err(AppError::Validation(
                "Analyst note must not exceed 1024 characters".to_string(),
            ));
        }
    }

    let uuid = Uuid::parse_str(alert_id.trim())
        .map_err(|e| AppError::Validation(format!("Invalid alert UUID: {e}")))?;
    let aid = AlertId::from_uuid(uuid);

    state
        .alert_repo
        .resolve_alert(aid, "security_analyst", note.as_deref())
        .await?;

    info!(alert_id = %aid, "Alert resolved by analyst");

    if let Some(ref handle) = *state.app_handle.read().await {
        let _ = handle.emit(
            EVENT_ALERT_STATUS_CHANGED,
            AlertStatusChangedPayload {
                alert_id: aid.to_string(),
                new_status: "resolved".to_string(),
                updated_at: Utc::now(),
            },
        );
    }

    Ok(())
}

#[tauri::command]
pub async fn resolve_alert(
    state: State<'_, Arc<AppState>>,
    alert_id: String,
    note: Option<String>,
) -> Result<(), AppError> {
    resolve_alert_impl(&state, alert_id, note).await
}

pub async fn get_detection_rules_impl(state: &AppState) -> Result<Vec<DetectionRuleDto>, AppError> {
    let rules = state.rule_repo.list_rules().await?;
    let mut dtos = Vec::with_capacity(rules.len());

    for rule in rules {
        let (threshold, window, cooldown, max_ev) = if rule.rule_id == "NET-001" {
            let th = rule
                .config_json
                .get("distinct_port_threshold")
                .and_then(|v| v.as_u64())
                .unwrap_or(10) as u32;
            let win = rule
                .config_json
                .get("window_duration_secs")
                .and_then(|v| v.as_i64())
                .unwrap_or(60);
            let cool = rule
                .config_json
                .get("cooldown_secs")
                .and_then(|v| v.as_i64());
            let max_e = rule
                .config_json
                .get("max_evidence_ids")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as usize;
            (th, win, cool, max_e)
        } else {
            let th = rule
                .config_json
                .get("observation_threshold")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as u32;
            let win = rule
                .config_json
                .get("window_duration_secs")
                .and_then(|v| v.as_i64())
                .unwrap_or(60);
            let cool = rule
                .config_json
                .get("cooldown_secs")
                .and_then(|v| v.as_i64());
            let max_e = rule
                .config_json
                .get("max_evidence_ids")
                .and_then(|v| v.as_u64())
                .unwrap_or(50) as usize;
            (th, win, cool, max_e)
        };

        dtos.push(DetectionRuleDto {
            rule_id: rule.rule_id,
            name: rule.name,
            description: rule.description,
            enabled: rule.enabled,
            rule_version: rule.rule_version,
            threshold,
            window_duration_secs: window,
            cooldown_secs: cooldown,
            max_evidence_ids: max_ev,
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        });
    }

    Ok(dtos)
}

#[tauri::command]
pub async fn get_detection_rules(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<DetectionRuleDto>, AppError> {
    get_detection_rules_impl(&state).await
}

pub async fn update_detection_rule_impl(
    state: &AppState,
    input: UpdateDetectionRuleInput,
) -> Result<(), AppError> {
    if input.rule_id != "NET-001" && input.rule_id != "NET-002" {
        return Err(AppError::Validation(format!(
            "Unsupported rule ID '{}'; only NET-001 and NET-002 are supported",
            input.rule_id
        )));
    }
    if input.threshold == 0 {
        return Err(AppError::Validation(
            "Rule threshold must be greater than zero".to_string(),
        ));
    }
    if input.window_duration_secs <= 0 || input.window_duration_secs > 86400 {
        return Err(AppError::Validation(
            "Window duration must be between 1 and 86400 seconds".to_string(),
        ));
    }
    if input.max_evidence_ids == 0 || input.max_evidence_ids > 1000 {
        return Err(AppError::Validation(
            "Max evidence IDs must be between 1 and 1000".to_string(),
        ));
    }
    if let Some(cooldown) = input.cooldown_secs {
        if cooldown < 0 || cooldown > 86400 {
            return Err(AppError::Validation(
                "Cooldown duration must be between 0 and 86400 seconds".to_string(),
            ));
        }
    }

    let existing = state.rule_repo.get_rule(&input.rule_id).await?;
    let Some(mut rule) = existing else {
        return Err(AppError::NotFound(format!(
            "Detection rule '{}' not found",
            input.rule_id
        )));
    };

    rule.enabled = input.enabled;
    rule.updated_at = Utc::now();

    if input.rule_id == "NET-001" {
        rule.config_json = serde_json::json!({
            "distinct_port_threshold": input.threshold,
            "window_duration_secs": input.window_duration_secs,
            "cooldown_secs": input.cooldown_secs,
            "max_evidence_ids": input.max_evidence_ids,
        });
    } else if input.rule_id == "NET-002" {
        rule.config_json = serde_json::json!({
            "observation_threshold": input.threshold,
            "window_duration_secs": input.window_duration_secs,
            "cooldown_secs": input.cooldown_secs,
            "max_evidence_ids": input.max_evidence_ids,
        });
    }

    state
        .rule_repo
        .upsert_rule(&rule, "security_operator")
        .await?;
    state.reload_detection_engine().await?;

    info!(rule_id = %input.rule_id, enabled = input.enabled, "Detection rule updated and engine reloaded");
    Ok(())
}

#[tauri::command]
pub async fn update_detection_rule(
    state: State<'_, Arc<AppState>>,
    input: UpdateDetectionRuleInput,
) -> Result<(), AppError> {
    update_detection_rule_impl(&state, input).await
}

pub async fn get_telemetry_status_impl(state: &AppState) -> Result<TelemetryStatusDto, AppError> {
    let ctrl = state.telemetry_control.lock().await;
    let coord = state.coordinator.lock().await;
    let stats = coord.collection_stats();

    let collector_type = if ctrl.mode == "mock" {
        "MockCollector"
    } else {
        "WindowsTcpCollector"
    };

    let collector_mode = if ctrl.mode == "mock" {
        "Deterministic Mock"
    } else {
        "Live Windows TCP Snapshot (GetExtendedTcpTable)"
    };

    let duration_f64 = stats.most_recent_duration.map(|d| d.as_secs_f64() * 1000.0);

    Ok(TelemetryStatusDto {
        collector_type: collector_type.to_string(),
        collector_mode: collector_mode.to_string(),
        is_running: ctrl.is_running,
        polling_interval_ms: ctrl.polling_interval_ms,
        last_attempt: ctrl.last_attempt,
        last_success: ctrl.last_success,
        last_successful_collection: ctrl.last_success,
        raw_records_observed: stats.raw_records_observed,
        normalized_events_produced: stats.normalized_events_produced,
        skipped_records: stats.records_skipped,
        collection_failures: stats.failed_cycles,
        recent_duration_ms: duration_f64,
        average_duration_ms: duration_f64.unwrap_or(0.0),
        last_error: ctrl.last_error.clone(),
        most_recent_error: ctrl.last_error.clone(),
    })
}

#[tauri::command]
pub async fn get_telemetry_status(
    state: State<'_, Arc<AppState>>,
) -> Result<TelemetryStatusDto, AppError> {
    get_telemetry_status_impl(&state).await
}

pub async fn start_telemetry_impl(state: &AppState) -> Result<(), AppError> {
    let mut ctrl = state.telemetry_control.lock().await;
    if ctrl.is_running {
        return Ok(());
    }

    ctrl.is_running = true;
    let mode = ctrl.mode.clone();
    let interval = ctrl.polling_interval_ms;

    let audit = AuditEntry::new(
        "operator",
        "telemetry_started",
        "telemetry",
        Some(mode.clone()),
        serde_json::json!({ "polling_interval_ms": interval }),
    );
    state.audit_repo.insert_entry(&audit).await?;

    if let Some(ref handle) = *state.app_handle.read().await {
        let _ = handle.emit(
            EVENT_COLLECTOR_STATE_CHANGED,
            CollectorStateChangedPayload {
                is_running: true,
                mode,
                polling_interval_ms: interval,
            },
        );
    }

    info!("Telemetry collection started by operator");
    Ok(())
}

#[tauri::command]
pub async fn start_telemetry(state: State<'_, Arc<AppState>>) -> Result<(), AppError> {
    start_telemetry_impl(&state).await
}

pub async fn stop_telemetry_impl(state: &AppState) -> Result<(), AppError> {
    let mut ctrl = state.telemetry_control.lock().await;
    if !ctrl.is_running {
        return Ok(());
    }

    ctrl.is_running = false;
    let mode = ctrl.mode.clone();
    let interval = ctrl.polling_interval_ms;

    let audit = AuditEntry::new(
        "operator",
        "telemetry_stopped",
        "telemetry",
        Some(mode.clone()),
        serde_json::json!({ "polling_interval_ms": interval }),
    );
    state.audit_repo.insert_entry(&audit).await?;

    if let Some(ref handle) = *state.app_handle.read().await {
        let _ = handle.emit(
            EVENT_COLLECTOR_STATE_CHANGED,
            CollectorStateChangedPayload {
                is_running: false,
                mode,
                polling_interval_ms: interval,
            },
        );
    }

    info!("Telemetry collection stopped by operator");
    Ok(())
}

#[tauri::command]
pub async fn stop_telemetry(state: State<'_, Arc<AppState>>) -> Result<(), AppError> {
    stop_telemetry_impl(&state).await
}

pub async fn get_audit_history_impl(
    state: &AppState,
    params: AuditQueryParams,
) -> Result<PaginatedResponse<AuditEntryDto>, AppError> {
    if let Some(ref a) = params.actor {
        if a.len() > 128 {
            return Err(AppError::Validation(
                "Audit query actor must not exceed 128 characters".to_string(),
            ));
        }
    }
    if let Some(ref a) = params.action {
        if a.len() > 128 {
            return Err(AppError::Validation(
                "Audit query action must not exceed 128 characters".to_string(),
            ));
        }
    }
    if let Some(ref t) = params.target_type {
        if t.len() > 128 {
            return Err(AppError::Validation(
                "Audit query target_type must not exceed 128 characters".to_string(),
            ));
        }
    }
    if let Some(ref t) = params.target_id {
        if t.len() > 128 {
            return Err(AppError::Validation(
                "Audit query target_id must not exceed 128 characters".to_string(),
            ));
        }
    }

    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0);
    if offset > 1_000_000 {
        return Err(AppError::Validation(
            "Query offset exceeds maximum limit of 1,000,000".to_string(),
        ));
    }

    let mut filter = AuditQueryFilter::new()
        .with_limit(limit)
        .with_offset(offset);

    if let Some(actor) = params.actor {
        if !actor.trim().is_empty() {
            filter.actor = Some(actor.trim().to_string());
        }
    }

    if let Some(action) = params.action {
        if !action.trim().is_empty() && action != "all" {
            filter.action = Some(action.trim().to_string());
        }
    }

    if let Some(target_type) = params.target_type {
        if !target_type.trim().is_empty() && target_type != "all" {
            filter.target_type = Some(target_type.trim().to_string());
        }
    }

    if let Some(target_id) = params.target_id {
        if !target_id.trim().is_empty() {
            filter.target_id = Some(target_id.trim().to_string());
        }
    }

    if let (Some(start), Some(end)) = (params.start_time, params.end_time) {
        if start > end {
            return Err(AppError::Validation(
                "Start time cannot be after end time".to_string(),
            ));
        }
        filter.start_time = Some(start);
        filter.end_time = Some(end);
    }

    let total = state.audit_repo.count_matching_entries(&filter).await?;
    let raw_entries = state.audit_repo.query_entries(&filter).await?;
    let items = raw_entries.iter().map(AuditEntryDto::from).collect();

    Ok(PaginatedResponse {
        items,
        total,
        total_count: total,
        limit: filter.limit,
        offset: filter.offset,
    })
}

#[tauri::command]
pub async fn get_audit_history(
    state: State<'_, Arc<AppState>>,
    params: AuditQueryParams,
) -> Result<PaginatedResponse<AuditEntryDto>, AppError> {
    get_audit_history_impl(&state, params).await
}

pub async fn get_application_settings_impl(state: &AppState) -> Result<AppSettings, AppError> {
    let settings = state.settings.lock().await;
    Ok(settings.clone())
}

#[tauri::command]
pub async fn get_application_settings(
    state: State<'_, Arc<AppState>>,
) -> Result<AppSettings, AppError> {
    get_application_settings_impl(&state).await
}

pub async fn update_application_settings_impl(
    state: &AppState,
    input: UpdateApplicationSettingsInput,
) -> Result<AppSettings, AppError> {
    let mut settings = {
        let current = state.settings.lock().await;
        current.clone()
    };

    if let Some(theme) = input.theme {
        let trimmed = theme.trim().to_lowercase();
        if trimmed != "dark" && trimmed != "light" && trimmed != "system" {
            return Err(AppError::Validation(
                "Theme must be one of: 'dark', 'light', 'system'".to_string(),
            ));
        }
        settings.theme = trimmed;
    }

    if let Some(refresh) = input.refresh_interval_secs {
        if refresh < 1 || refresh > 3600 {
            return Err(AppError::Validation(
                "Refresh interval must be between 1 and 3600 seconds".to_string(),
            ));
        }
        settings.refresh_interval_secs = refresh;
    }

    if let Some(page_size) = input.event_table_page_size {
        if page_size < 10 || page_size > 500 {
            return Err(AppError::Validation(
                "Page size must be between 10 and 500".to_string(),
            ));
        }
        settings.event_table_page_size = page_size;
    }

    if let Some(ev_retention) = input.event_retention_days {
        if ev_retention < 1 || ev_retention > 365 {
            return Err(AppError::Validation(
                "Event retention days must be between 1 and 365".to_string(),
            ));
        }
        settings.event_retention_days = ev_retention;
    }

    if let Some(aud_retention) = input.audit_retention_days {
        if aud_retention < 7 || aud_retention > 3650 {
            return Err(AppError::Validation(
                "Audit retention days must be between 7 and 3650".to_string(),
            ));
        }
        settings.audit_retention_days = aud_retention;
    }

    if let Some(polling) = input.telemetry_polling_interval_ms {
        if polling < 100 || polling > 3600_000 {
            return Err(AppError::Validation(
                "Telemetry polling interval must be between 100ms and 3600000ms".to_string(),
            ));
        }
        settings.telemetry_polling_interval_ms = polling;
    }

    if let Some(verbosity) = input.log_verbosity {
        let trimmed = verbosity.trim().to_lowercase();
        if !["trace", "debug", "info", "warn", "error"].contains(&trimmed.as_str()) {
            return Err(AppError::Validation(
                "Log verbosity must be one of: 'trace', 'debug', 'info', 'warn', 'error'"
                    .to_string(),
            ));
        }
        settings.log_verbosity = trimmed;
    }

    if let Some(demo_mode) = input.is_demo_mode {
        if demo_mode != settings.is_demo_mode {
            settings.is_demo_mode = demo_mode;

            let mut coord = state.coordinator.lock().await;
            let mut ctrl = state.telemetry_control.lock().await;

            if demo_mode {
                coord.set_collector(Box::new(MockCollector::for_scenario(&MockScenario::Mixed)));
                ctrl.mode = "mock".to_string();
            } else {
                coord.set_collector(Box::new(WindowsTcpCollector::new()));
                ctrl.mode = "live_windows_tcp".to_string();
            }

            info!(demo_mode, "Swapped telemetry collector source mode");
        }
    }

    state.save_settings(settings.clone(), "operator").await?;
    Ok(settings)
}

#[tauri::command]
pub async fn update_application_settings(
    state: State<'_, Arc<AppState>>,
    input: UpdateApplicationSettingsInput,
) -> Result<AppSettings, AppError> {
    update_application_settings_impl(&state, input).await
}
