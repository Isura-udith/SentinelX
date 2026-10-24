/**
 * SentinelX Desktop Type Definitions
 * Matches backend Rust serialization in sentinel-app.
 */

export type AlertSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type AlertStatus = 'Open' | 'Acknowledged' | 'Resolved';

export interface SystemStatus {
  telemetry_running: boolean;
  collector_mode: string;
  database_connected: boolean;
  database_path: string;
  detection_engine_healthy: boolean;
  last_collection_time: string | null;
  is_demo_mode: boolean;
  app_version: string;
}

export interface AlertSeverityDistribution {
  informational: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface TimeSeriesBucket {
  timestamp: string;
  event_count: number;
  alert_count: number;
}

export interface NetworkEventSummary {
  id: string;
  timestamp: string;
  telemetry_source: string;
  protocol: string;
  source_ip: string;
  source_port: number;
  destination_ip: string;
  destination_port: number;
  process_id: number | null;
}

export interface NetworkEventDetails extends NetworkEventSummary {
  socket_state: string;
  metadata: Record<string, unknown>;
}

export interface SecurityAlertSummary {
  id: string;
  rule_id: string;
  rule_version: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  status: AlertStatus;
  event_count: number;
  fingerprint: string;
  evidence_event_count: number;
}

export interface SecurityAlertDetails extends SecurityAlertSummary {
  evidence_event_ids: string[];
  associated_audit_history: AuditEntry[];
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  enabled: boolean;
  rule_version: string;
  created_at: string;
  updated_at: string;
  threshold: number;
  window_duration_secs: number;
  cooldown_secs: number | null;
  max_evidence_ids: number;
}

export interface TelemetryStatus {
  collector_type: string;
  is_running: boolean;
  last_attempt: string | null;
  last_success: string | null;
  polling_interval_ms: number;
  raw_records_observed: number;
  normalized_events_produced: number;
  skipped_records: number;
  collection_failures: number;
  recent_duration_ms: number | null;
  last_error: string | null;
}

export interface DashboardSummary {
  total_events: number;
  open_alerts: number;
  high_critical_alerts: number;
  events_last_hour: number;
  successful_collections: number;
  detection_healthy: boolean;
  activity_time_series: TimeSeriesBucket[];
  severity_distribution: AlertSeverityDistribution;
  recent_alerts: SecurityAlertSummary[];
  recent_events: NetworkEventSummary[];
  collector_status: TelemetryStatus;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  target_type: string;
  target_id: string | null;
  details: Record<string, unknown>;
}

export interface AppSettings {
  theme: string;
  refresh_interval_secs: number;
  event_table_page_size: number;
  database_path: string;
  event_retention_days: number;
  audit_retention_days: number;
  telemetry_polling_interval_ms: number;
  log_verbosity: string;
  is_demo_mode: boolean;
}

export interface PaginatedResult<T> {
  items: T[];
  total_count: number;
  limit: number;
  offset: number;
}

// Query parameters
export interface EventQueryParams {
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  telemetry_source?: string;
  search_text?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
  sort_desc?: boolean;
}

export interface AlertQueryParams {
  severity?: AlertSeverity;
  status?: AlertStatus;
  rule_id?: string;
  source_ip?: string;
  search_text?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
}

export interface AuditQueryParams {
  actor?: string;
  action?: string;
  target_type?: string;
  target_id?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
}

export interface UpdateDetectionRuleInput {
  rule_id: string;
  enabled: boolean;
  threshold: number;
  window_duration_secs: number;
  cooldown_secs?: number | null;
  max_evidence_ids: number;
}

export interface UpdateAppSettingsInput {
  theme?: string;
  refresh_interval_secs?: number;
  event_table_page_size?: number;
  event_retention_days?: number;
  audit_retention_days?: number;
  telemetry_polling_interval_ms?: number;
  log_verbosity?: string;
  is_demo_mode?: boolean;
}
