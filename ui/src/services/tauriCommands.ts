/**
 * Typed Tauri Command Service for SentinelX
 * Invokes Rust backend commands registered in sentinel-app.
 */

import { invoke } from '@tauri-apps/api/core';
import type {
  SystemStatus,
  DashboardSummary,
  PaginatedResult,
  NetworkEventSummary,
  NetworkEventDetails,
  SecurityAlertSummary,
  SecurityAlertDetails,
  DetectionRule,
  TelemetryStatus,
  AuditEntry,
  AppSettings,
  EventQueryParams,
  AlertQueryParams,
  AuditQueryParams,
  UpdateDetectionRuleInput,
  UpdateAppSettingsInput,
} from '../types';

// Helper to determine if running inside Tauri webview
export const isTauriEnvironment = (): boolean => {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
};

// Safe invoke wrapper with structured error handling
async function callBackend<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  if (isTauriEnvironment()) {
    try {
      return await invoke<T>(command, args);
    } catch (err: unknown) {
      if (typeof err === 'object' && err !== null && 'message' in err) {
        throw new Error((err as { message: string }).message);
      }
      throw new Error(String(err));
    }
  }

  // Graceful in-browser test fallback
  return getMockResponse<T>(command, args);
}

// ============================================================================
// 17 Typed Commands
// ============================================================================

export const tauriCommands = {
  getSystemStatus: (): Promise<SystemStatus> =>
    callBackend<SystemStatus>('get_system_status'),

  getDashboardSummary: (timeRange?: string): Promise<DashboardSummary> =>
    callBackend<DashboardSummary>('get_dashboard_summary', { timeRange }),

  queryNetworkEvents: (params: EventQueryParams): Promise<PaginatedResult<NetworkEventSummary>> =>
    callBackend<PaginatedResult<NetworkEventSummary>>('query_network_events', { params }),

  getNetworkEventDetails: (eventId: string): Promise<NetworkEventDetails> =>
    callBackend<NetworkEventDetails>('get_network_event_details', { eventId }),

  querySecurityAlerts: (params: AlertQueryParams): Promise<PaginatedResult<SecurityAlertSummary>> =>
    callBackend<PaginatedResult<SecurityAlertSummary>>('query_security_alerts', { params }),

  getSecurityAlertDetails: (alertId: string): Promise<SecurityAlertDetails> =>
    callBackend<SecurityAlertDetails>('get_security_alert_details', { alertId }),

  getAlertEvidence: (alertId: string): Promise<NetworkEventSummary[]> =>
    callBackend<NetworkEventSummary[]>('get_alert_evidence', { alertId }),

  acknowledgeAlert: (alertId: string, note?: string): Promise<void> =>
    callBackend<void>('acknowledge_alert', { alertId, note }),

  resolveAlert: (alertId: string, note?: string): Promise<void> =>
    callBackend<void>('resolve_alert', { alertId, note }),

  getDetectionRules: (): Promise<DetectionRule[]> =>
    callBackend<DetectionRule[]>('get_detection_rules'),

  updateDetectionRule: (input: UpdateDetectionRuleInput): Promise<void> =>
    callBackend<void>('update_detection_rule', { input }),

  getTelemetryStatus: (): Promise<TelemetryStatus> =>
    callBackend<TelemetryStatus>('get_telemetry_status'),

  startTelemetry: (): Promise<void> =>
    callBackend<void>('start_telemetry'),

  stopTelemetry: (): Promise<void> =>
    callBackend<void>('stop_telemetry'),

  getAuditHistory: (params: AuditQueryParams): Promise<PaginatedResult<AuditEntry>> =>
    callBackend<PaginatedResult<AuditEntry>>('get_audit_history', { params }),

  getApplicationSettings: (): Promise<AppSettings> =>
    callBackend<AppSettings>('get_application_settings'),

  updateApplicationSettings: (input: UpdateAppSettingsInput): Promise<AppSettings> =>
    callBackend<AppSettings>('update_application_settings', { input }),
};

// ============================================================================
// Development & Vitest In-Browser Mock Provider
// ============================================================================

function getMockResponse<T>(command: string, args: Record<string, unknown>): T {
  const now = new Date().toISOString();

  switch (command) {
    case 'get_system_status':
      return {
        telemetry_running: true,
        collector_mode: 'WindowsTcp',
        database_connected: true,
        database_path: 'C:\\Users\\Mock\\AppData\\Local\\SentinelX\\sentinelx.db',
        detection_engine_healthy: true,
        last_collection_time: now,
        is_demo_mode: false,
        app_version: '0.2.0',
      } as T;

    case 'get_dashboard_summary':
      return {
        total_events: 1240,
        open_alerts: 3,
        high_critical_alerts: 1,
        events_last_hour: 410,
        successful_collections: 58,
        detection_healthy: true,
        activity_time_series: Array.from({ length: 12 }, (_, i) => ({
          timestamp: new Date(Date.now() - (11 - i) * 3600000).toISOString(),
          event_count: Math.floor(Math.random() * 80) + 20,
          alert_count: i === 10 ? 1 : 0,
        })),
        severity_distribution: {
          informational: 0,
          low: 1,
          medium: 1,
          high: 1,
          critical: 0,
        },
        recent_alerts: [
          {
            id: 'alt-001',
            rule_id: 'NET-001',
            rule_version: '1.0.0',
            severity: 'High',
            title: 'Horizontal Port Scan Detected',
            description: 'Observed 12 distinct destination ports from 192.168.1.105',
            first_seen: now,
            last_seen: now,
            created_at: now,
            updated_at: now,
            status: 'Open',
            event_count: 12,
            fingerprint: 'NET-001:192.168.1.105',
            evidence_event_count: 12,
          },
        ],
        recent_events: [
          {
            id: 'evt-001',
            timestamp: now,
            telemetry_source: 'WindowsTcp',
            protocol: 'TCP',
            source_ip: '192.168.1.105',
            source_port: 49152,
            destination_ip: '192.168.1.1',
            destination_port: 80,
            process_id: 4210,
          },
        ],
        collector_status: {
          collector_type: 'Windows TCP Snapshot Collector',
          is_running: true,
          last_attempt: now,
          last_success: now,
          polling_interval_ms: 1000,
          raw_records_observed: 1340,
          normalized_events_produced: 1240,
          skipped_records: 100,
          collection_failures: 0,
          recent_duration_ms: 4.2,
          last_error: null,
        },
      } as T;

    case 'query_network_events':
      return {
        items: [
          {
            id: 'evt-001',
            timestamp: now,
            telemetry_source: 'WindowsTcp',
            protocol: 'TCP',
            source_ip: '192.168.1.105',
            source_port: 49152,
            destination_ip: '192.168.1.1',
            destination_port: 80,
            process_id: 4210,
          },
        ],
        total_count: 1,
        limit: 50,
        offset: 0,
      } as T;

    case 'get_network_event_details':
      return {
        id: args.eventId as string,
        timestamp: now,
        telemetry_source: 'WindowsTcp',
        protocol: 'TCP',
        source_ip: '192.168.1.105',
        source_port: 49152,
        destination_ip: '192.168.1.1',
        destination_port: 80,
        process_id: 4210,
        socket_state: 'Established',
        metadata: { collector_version: '0.2.0' },
      } as T;

    case 'query_security_alerts':
      return {
        items: [
          {
            id: 'alt-001',
            rule_id: 'NET-001',
            rule_version: '1.0.0',
            severity: 'High',
            title: 'Horizontal Port Scan Detected',
            description: 'Observed 12 distinct destination ports from 192.168.1.105',
            first_seen: now,
            last_seen: now,
            created_at: now,
            updated_at: now,
            status: 'Open',
            event_count: 12,
            fingerprint: 'NET-001:192.168.1.105',
            evidence_event_count: 12,
          },
        ],
        total_count: 1,
        limit: 50,
        offset: 0,
      } as T;

    case 'get_security_alert_details':
      return {
        id: args.alertId as string,
        rule_id: 'NET-001',
        rule_version: '1.0.0',
        severity: 'High',
        title: 'Horizontal Port Scan Detected',
        description: 'Observed 12 distinct destination ports from 192.168.1.105',
        first_seen: now,
        last_seen: now,
        created_at: now,
        updated_at: now,
        status: 'Open',
        event_count: 12,
        fingerprint: 'NET-001:192.168.1.105',
        evidence_event_count: 12,
        evidence_event_ids: ['evt-001'],
        associated_audit_history: [
          {
            id: 1,
            timestamp: now,
            actor: 'SystemDetectionEngine',
            action: 'alert_created',
            target_type: 'alert',
            target_id: args.alertId as string,
            details: { reason: 'threshold_exceeded' },
          },
        ],
      } as T;

    case 'get_alert_evidence':
      return [
        {
          id: 'evt-001',
          timestamp: now,
          telemetry_source: 'WindowsTcp',
          protocol: 'TCP',
          source_ip: '192.168.1.105',
          source_port: 49152,
          destination_ip: '192.168.1.1',
          destination_port: 80,
          process_id: 4210,
        },
      ] as T;

    case 'get_detection_rules':
      return [
        {
          rule_id: 'NET-001',
          name: 'Horizontal Port Scan Detection',
          description: 'Detects single source scanning distinct destination ports',
          enabled: true,
          rule_version: '1.0.0',
          created_at: now,
          updated_at: now,
          threshold: 10,
          window_duration_secs: 60,
          cooldown_secs: 300,
          max_evidence_ids: 20,
        },
        {
          rule_id: 'NET-002',
          name: 'High-Frequency Connection Burst',
          description: 'Detects rapid bursts of connection attempts',
          enabled: true,
          rule_version: '1.0.0',
          created_at: now,
          updated_at: now,
          threshold: 50,
          window_duration_secs: 10,
          cooldown_secs: 120,
          max_evidence_ids: 25,
        },
      ] as T;

    case 'get_telemetry_status':
      return {
        collector_type: 'Windows TCP Snapshot Collector',
        is_running: true,
        last_attempt: now,
        last_success: now,
        polling_interval_ms: 1000,
        raw_records_observed: 1500,
        normalized_events_produced: 1400,
        skipped_records: 100,
        collection_failures: 0,
        recent_duration_ms: 3.8,
        last_error: null,
      } as T;

    case 'get_audit_history':
      return {
        items: [
          {
            id: 1,
            timestamp: now,
            actor: 'Analyst (Local User)',
            action: 'settings_updated',
            target_type: 'settings',
            target_id: null,
            details: { updated_fields: ['refresh_interval_secs'] },
          },
        ],
        total_count: 1,
        limit: 50,
        offset: 0,
      } as T;

    case 'getApplicationSettings':
    case 'get_application_settings':
      return {
        theme: 'dark',
        refresh_interval_secs: 10,
        event_table_page_size: 50,
        database_path: 'C:\\Users\\Mock\\AppData\\Local\\SentinelX\\sentinelx.db',
        event_retention_days: 30,
        audit_retention_days: 90,
        telemetry_polling_interval_ms: 1000,
        log_verbosity: 'INFO',
        is_demo_mode: false,
      } as T;

    case 'update_application_settings':
      return {
        theme: 'dark',
        refresh_interval_secs: 10,
        event_table_page_size: 50,
        database_path: 'C:\\Users\\Mock\\AppData\\Local\\SentinelX\\sentinelx.db',
        event_retention_days: 30,
        audit_retention_days: 90,
        telemetry_polling_interval_ms: 1000,
        log_verbosity: 'INFO',
        is_demo_mode: false,
        ...(args.input as Record<string, unknown>),
      } as T;

    case 'acknowledge_alert':
    case 'resolve_alert':
    case 'update_detection_rule':
    case 'start_telemetry':
    case 'stop_telemetry':
      return undefined as T;

    default:
      throw new Error(`Unknown command in mock provider: ${command}`);
  }
}
