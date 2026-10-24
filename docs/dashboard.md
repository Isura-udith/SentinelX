# SentinelX Desktop Dashboard Guide

## 1. Overview and Architecture

SentinelX Desktop is a native Windows 11 cybersecurity monitoring and threat detection desktop application built with **Tauri 2**, **React 19**, **TypeScript** (strict mode), and **Tailwind CSS**.

It connects directly via local in-process IPC to the existing Rust backend crates:
- `sentinel-core`: Domain models, strongly-typed network events, security alerts, and detection configuration.
- `sentinel-collector`: Windows TCP connection snapshot collector using native `GetExtendedTcpTable` (and deterministic mock collectors).
- `sentinel-detection`: Rolling-window detection engine executing rules `NET-001` (Port Scan Detection) and `NET-002` (High-Frequency Connection Burst).
- `sentinel-storage`: SQLite persistence layer with transactions, migration management, and retention policies.
- `sentinel-app`: Application state coordinator, configuration manager, background polling worker, and 17 typed Tauri commands.

```
┌────────────────────────────────────────────────────────┐
│                   SentinelX Desktop                    │
│             React 19 + TypeScript + Vite               │
│         Cybersecurity SOC Theme (Tailwind CSS)         │
└───────────────────────────┬────────────────────────────┘
                            │ Tauri 2 IPC (invoke & events)
┌───────────────────────────▼────────────────────────────┐
│                      sentinel-app                      │
│   AppState · PipelineCoordinator · Background Worker   │
└──────┬────────────────────┬────────────────────┬───────┘
       │                    │                    │
┌──────▼──────┐      ┌──────▼──────┐      ┌──────▼───────┐
│  Collector  │      │  Detection  │      │   Storage    │
│ Windows TCP │      │ NET-001/002 │      │ SQLite/SQLx  │
└─────────────┘      └─────────────┘      └──────────────┘
```

---

## 2. Global Navigation & Pages

The application provides seven primary navigation views:

1. **Overview Dashboard (`OverviewPage.tsx`)**:
   - High-level KPI metrics derived strictly from backend state: Total events, Open alerts, High/Critical alerts, Events in the last hour, Successful collection cycles, and Detection engine status.
   - 12-bucket time-series observation activity chart (Recharts) showing normalized event volume and threat alert points.
   - Active alert severity distribution breakdown.
   - Recent alerts table with direct navigation to investigation details.
   - Recent network events table with protocol, source/destination IP/port, and process ID.
   - Collector operational state and execution health summary.

2. **Network Events (`EventsPage.tsx`)**:
   - Server-side paginated investigation table for historical and live network observations.
   - Full-text search and multi-parameter filtering: Protocol (TCP/UDP), Source IP, Destination IP, Destination Port, and Telemetry Source.
   - Sortable columns and configurable page size (10, 25, 50, 100).
   - Event detail drawer rendering validated metadata and socket state.

3. **Security Alerts (`AlertsPage.tsx`)**:
   - Triaged threat detections table with status badges (`Open`, `Acknowledged`, `Resolved`) and severity tiers (`Critical`, `High`, `Medium`, `Low`, `Informational`).
   - Filters by severity, status, rule ID, and text search.
   - Modal-backed analyst state transitions (`Acknowledge` and `Resolve`) with optional analyst notes persisted to SQLite audit history.

4. **Alert Investigation & Evidence (`AlertDetailsPage.tsx`)**:
   - Detailed forensics view displaying correlation fingerprints, observation counts, first/last seen timestamps, and rule version.
   - Supporting network event observations table.
   - Explicit alert for expired evidence when underlying raw events have been pruned by SQLite retention policy while maintaining alert integrity.
   - Visual investigation timeline with chronological audit trail.

5. **Detection Rules (`DetectionRulesPage.tsx`)**:
   - Authoritative rule management interface for `NET-001` (Port Scan) and `NET-002` (Connection Burst).
   - Real-time display of thresholds, observation windows, cooldowns, and max evidence limits.
   - Modal configuration editor with strict boundary validation (non-zero thresholds, positive windows).
   - High-risk confirmation dialog before disabling rules to prevent accidental suspension of defensive monitoring.

6. **Telemetry Operations (`TelemetryPage.tsx`)**:
   - Native Windows TCP snapshot collector lifecycle controls (idempotent Start and Stop operations).
   - Live metrics: Raw records observed, normalized events produced, skipped listening sockets, consecutive failures, and collection duration in milliseconds.
   - Detailed timestamp logs of the most recent collection attempt and success.

7. **Compliance Audit Trail (`AuditPage.tsx`)**:
   - Read-only historical viewer of system transitions, analyst acknowledgements, resolutions, rule updates, and setting changes.
   - Filters by action type, target type, and actor identity.
   - Detailed JSON payload inspection modal.

8. **Application Settings (`SettingsPage.tsx`)**:
   - Retention policy management: Event retention days and Audit retention days with explicit evidence preservation warnings.
   - Telemetry polling interval controls (100 ms to 3,600,000 ms).
   - Live mode vs. Demonstration / Mock mode toggle.
   - Read-only display of the SQLite database file path in `%LOCALAPPDATA%\SentinelX\sentinelx.db`.
   - UI automatic refresh interval and default page size settings.

---

## 3. Typed Tauri Backend Commands

SentinelX exposes 17 strongly-typed commands with strict input validation and safe error mapping:

| Command Name | Description | Defensive Validation |
| :--- | :--- | :--- |
| `get_system_status` | Returns overall health of collector, DB, and engine | None (read-only query) |
| `get_dashboard_summary` | Returns aggregated metrics, activity chart buckets, and recents | Validates time range identifier (`1h`, `6h`, `24h`, `7d`) |
| `query_network_events` | Paginated query of normalized network events | Validates port range (1-65535), bounds offset/limit, validates IP formats |
| `get_network_event_details` | Retrieves full normalized event and raw metadata | Validates UUID format |
| `query_security_alerts` | Paginated query of security alerts | Validates severity and status strings against enum variants |
| `get_security_alert_details` | Retrieves alert header, evidence IDs, and audit history | Validates UUID format |
| `get_alert_evidence` | Retrieves supporting network events for an alert | Returns empty list gracefully if pruned by retention |
| `acknowledge_alert` | Transitions alert to Acknowledged | Enforces valid status transition; audits analyst action |
| `resolve_alert` | Transitions alert to Resolved | Enforces valid status transition; audits analyst action |
| `get_detection_rules` | Returns authoritative detection rules and configurations | None (read-only query) |
| `update_detection_rule` | Updates rule thresholds, window, cooldown, and enabled state | Rejects threshold <= 0, window <= 0, cooldown < 0; updates active engine |
| `get_telemetry_status` | Returns live metrics from collector stats and control state | None (read-only query) |
| `start_telemetry` | Starts the background collection loop | Idempotent; guards against duplicate workers |
| `stop_telemetry` | Pauses the background collection loop | Idempotent |
| `get_audit_history` | Paginated query of immutable audit log entries | Bounded limit and offset |
| `get_application_settings` | Loads current application configuration | Reads from `%LOCALAPPDATA%\SentinelX\settings.json` |
| `update_application_settings` | Updates and persists configuration to disk | Validates intervals and retention bounds before persisting |

---

## 4. Live Updates and Event Bus

SentinelX uses Tauri 2 IPC events to stream state changes from Rust to React without polling loops:

- `sentinel://new-event`: Emitted on new batch ingestion.
- `sentinel://new-alert`: Emitted when the detection engine triggers a threat alert.
- `sentinel://alert-status-changed`: Emitted when an alert is acknowledged or resolved.
- `sentinel://collector-state-changed`: Emitted when telemetry collection starts, stops, or encounters errors.

React listeners automatically subscribe once on component mount and clean up on unmount.
