/**
 * Deterministic Test Fixtures for SentinelX Frontend Tests
 * Used EXCLUSIVELY by Vitest harness in ui/src/test/
 * Not included in production application runtime.
 */

export function getTestFixtureResponse<T>(command: string, args: Record<string, unknown> = {}): T {
  const now = new Date('2026-10-26T12:00:00.000Z').toISOString();

  switch (command) {
    case 'get_system_status':
      return {
        telemetry_running: true,
        collector_mode: 'LiveWindowsTcp',
        database_connected: true,
        database_path: 'C:\\Users\\Analyst\\AppData\\Local\\SentinelX\\sentinelx.db',
        detection_engine_healthy: true,
        last_collection_time: now,
        is_demo_mode: false,
        app_version: '1.0.0',
      } as T;

    case 'get_dashboard_summary':
      return {
        total_events: 100,
        open_alerts: 1,
        high_critical_alerts: 1,
        events_last_hour: 45,
        successful_collections: 12,
        detection_healthy: true,
        activity_time_series: Array.from({ length: 12 }, (_, i) => ({
          timestamp: new Date(Date.now() - (11 - i) * 3600000).toISOString(),
          event_count: 10 + i,
          alert_count: i === 10 ? 1 : 0,
        })),
        severity_distribution: {
          informational: 0,
          low: 0,
          medium: 0,
          high: 1,
          critical: 0,
        },
        recent_alerts: [
          {
            id: '550e8400-e29b-41d4-a716-446655440000',
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
            id: 'e10e8400-e29b-41d4-a716-446655440001',
            timestamp: now,
            telemetry_source: 'windows_tcp_snapshot',
            protocol: 'TCP',
            source_ip: '192.168.1.105',
            source_port: 49152,
            destination_ip: '192.168.1.1',
            destination_port: 80,
            process_id: 4210,
          },
        ],
        collector_status: {
          collector_type: 'Windows TCP Connection Snapshot Collector',
          is_running: true,
          last_attempt: now,
          last_success: now,
          polling_interval_ms: 1000,
          raw_records_observed: 120,
          normalized_events_produced: 100,
          skipped_records: 20,
          collection_failures: 0,
          recent_duration_ms: 4.2,
          last_error: null,
        },
      } as T;

    case 'query_network_events':
      return {
        items: [
          {
            id: 'e10e8400-e29b-41d4-a716-446655440001',
            timestamp: now,
            telemetry_source: 'windows_tcp_snapshot',
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
        id: (args.eventId as string) || 'e10e8400-e29b-41d4-a716-446655440001',
        timestamp: now,
        telemetry_source: 'windows_tcp_snapshot',
        protocol: 'TCP',
        source_ip: '192.168.1.105',
        source_port: 49152,
        destination_ip: '192.168.1.1',
        destination_port: 80,
        process_id: 4210,
        socket_state: 'ESTABLISHED',
        metadata: { collector_version: '1.0.0' },
      } as T;

    case 'query_security_alerts':
      return {
        items: [
          {
            id: '550e8400-e29b-41d4-a716-446655440000',
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
        id: (args.alertId as string) || '550e8400-e29b-41d4-a716-446655440000',
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
        evidence_event_ids: ['e10e8400-e29b-41d4-a716-446655440001'],
        associated_audit_history: [
          {
            id: 'a10e8400-e29b-41d4-a716-446655440002',
            timestamp: now,
            actor: 'SystemDetectionEngine',
            action: 'alert_created',
            target_type: 'alert',
            target_id: (args.alertId as string) || '550e8400-e29b-41d4-a716-446655440000',
            details: { reason: 'threshold_exceeded' },
          },
        ],
      } as T;

    case 'get_alert_evidence':
      return [
        {
          id: 'e10e8400-e29b-41d4-a716-446655440001',
          timestamp: now,
          telemetry_source: 'windows_tcp_snapshot',
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
        raw_records_observed: 150,
        normalized_events_produced: 140,
        skipped_records: 10,
        collection_failures: 0,
        recent_duration_ms: 3.8,
        last_error: null,
      } as T;

    case 'get_audit_history':
      return {
        items: [
          {
            id: 'a10e8400-e29b-41d4-a716-446655440003',
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
        database_path: 'C:\\Users\\Analyst\\AppData\\Local\\SentinelX\\sentinelx.db',
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
        database_path: 'C:\\Users\\Analyst\\AppData\\Local\\SentinelX\\sentinelx.db',
        event_retention_days: 30,
        audit_retention_days: 90,
        telemetry_polling_interval_ms: 1000,
        log_verbosity: 'INFO',
        is_demo_mode: false,
        ...(args.input as Record<string, unknown>),
      } as T;

    case 'get_system_diagnostics':
      return {
        app_version: '1.0.0',
        backend_initialized: true,
        database_connected: true,
        database_schema_version: 'v3',
        database_file_size_bytes: 49152,
        collector_status: 'live_windows_tcp',
        collector_is_running: true,
        last_collection_time: now,
        total_persisted_events: 100,
        total_persisted_alerts: 1,
        latest_application_error: null,
      } as T;

    case 'acknowledge_alert':
    case 'resolve_alert':
    case 'update_detection_rule':
    case 'start_telemetry':
    case 'stop_telemetry':
      return undefined as T;

    default:
      throw new Error(`Unknown command in test fixture provider: ${command}`);
  }
}
