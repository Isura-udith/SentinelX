/**
 * Typed Tauri Command Service for SentinelX
 * Invokes Rust backend commands registered in sentinel-app.
 *
 * NOTE: Production application code strictly communicates with the real Rust
 * backend over Tauri 2.0 IPC. No fabricated or mock fallback data is returned.
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
  SystemDiagnostics,
  EventQueryParams,
  AlertQueryParams,
  AuditQueryParams,
  UpdateDetectionRuleInput,
  UpdateAppSettingsInput,
} from '../types';

// Helper to determine if running inside Tauri webview
export const isTauriEnvironment = (): boolean => {
  return typeof window !== 'undefined' && ('__TAURI_INTERNALS__' in window || '__TAURI__' in window);
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

  throw new Error(
    `Tauri backend IPC unavailable: Cannot invoke '${command}'. SentinelX requires the Windows desktop Tauri runtime.`
  );
}

// ============================================================================
// 18 Strongly-Typed Tauri Commands
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

  getSystemDiagnostics: (): Promise<SystemDiagnostics> =>
    callBackend<SystemDiagnostics>('get_system_diagnostics'),
};
