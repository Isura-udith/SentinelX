# SentinelX Release Test Plan & Execution Report

**Release Candidate:** SentinelX v1.0.0  
**Test Execution Date:** 2026-10-25  
**Platform:** Windows 11 Pro (x86_64)  
**Total Tests Executed:** 88 automated tests + 5 packaging & binary verification tests  
**Overall Result:** **ALL TESTS PASSED (100% Pass Rate)**

---

## 1. Automated Test Suite Matrix

### 1.1 Telemetry Collection & Windows API (`sentinel-collector`)
| Test ID | Test Target | Steps | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TEL-01** | `test_native_windows_collection_live` | Invoke `WindowsTcpCollector::collect()` on Windows 11 host. | Retrieves live TCP connection table with valid PIDs and socket states. | Retrieved active established/listening sockets without panics. | **PASS** |
| **TEL-02** | `test_listening_socket_skipped` | Feed socket in `MIB_TCP_STATE_LISTEN` into normalizer. | Socket is skipped from normal active telemetry. | Listening records filtered; 0 events produced. | **PASS** |
| **TEL-03** | `test_ipv4_and_port_byte_order_decoding` | Feed big-endian network byte order port `0x0050` (80). | Decoded port equals `80` (HTTP). | Correctly decoded port 80 and dotted decimal IP. | **PASS** |
| **TEL-04** | `test_ipv6_normalization` | Feed standard IPv6 loopback and remote address into normalizer. | Normalizes to `IpAddr::V6` with accurate socket states. | IPv6 normalized correctly. | **PASS** |
| **TEL-05** | `test_empty_telemetry_snapshot_handling` | Ingest snapshot containing zero connection entries. | Pipeline records empty cycle gracefully; no alerts emitted. | Handled cleanly; 0 events, 0 alerts. | **PASS** |
| **TEL-06** | `test_collector_failure_injection_handling` | Inject `CollectorError::NativeApiFailure` into coordinator. | System records degraded status, increments error count, does not crash. | Coordinator logged error and preserved state. | **PASS** |

### 1.2 Defensive Threat Detection (`sentinel-detection`)
| Test ID | Test Target | Steps | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DET-01** | `test_port_scan_rule_detection_success` | Ingest events from `192.168.1.50` hitting 12 distinct destination ports within 60s. | Triggers NET-001 alert with `AlertSeverity::Medium` and evidence list. | NET-001 alert created with all 12 port evidence references. | **PASS** |
| **DET-02** | `test_duplicate_ports_do_not_inflate_count`| Ingest 20 events hitting port 443 repeatedly from same IP. | Distinct port count remains 1; no port-scan alert triggered. | Port count = 1; zero alerts generated. | **PASS** |
| **DET-03** | `test_alert_cooldown` | Send second scan burst from same IP immediately following alert. | Second burst suppressed during active cooldown window. | Duplicate alert suppressed during cooldown. | **PASS** |
| **DET-04** | `test_out_of_order_events` | Ingest events where `timestamp` arrives backwards by 15 seconds. | Engine reconciles rolling window accurately without panicking. | Out-of-order events processed within window. | **PASS** |
| **DET-05** | `test_rolling_window_expiration` | Ingest 5 events, advance clock past window duration, ingest 5 events. | Prior events expire; distinct count resets; no alert. | State expired cleanly; threshold not breached. | **PASS** |
| **DET-06** | `test_multiple_source_addresses_isolated` | Ingest 8 events each from IP-A and IP-B (threshold 10). | Counters remain isolated per IP; neither triggers false alert. | State tracked separately; zero alerts. | **PASS** |
| **DET-07** | `test_connection_burst_threshold_trigger` | Ingest 25 connections in 10s (NET-002 threshold 20). | Triggers NET-002 alert with `AlertSeverity::High`. | NET-002 burst alert emitted with evidence. | **PASS** |

### 1.3 SQLite Persistence & Migrations (`sentinel-storage`)
| Test ID | Test Target | Steps | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **STO-01** | `test_database_initialization_and_migrations` | Connect to fresh SQLite database file. | Embedded SQLx migrations execute; tables created; WAL active. | Migrations 0001–0003 applied; WAL mode confirmed. | **PASS** |
| **STO-02** | `test_foreign_key_enforcement` | Attempt to insert alert evidence referencing non-existent event ID. | Database rejects insertion with foreign key constraint error. | SQLite returned `FOREIGN KEY constraint failed`. | **PASS** |
| **STO-03** | `test_batch_insertion_and_transaction_rollback` | Ingest 50 events where 50th contains constraint error. | Entire transaction rolls back; zero partial rows committed. | Transaction rolled back; database row count remains 0. | **PASS** |
| **STO-04** | `test_retention_cleanup_with_evidence_preservation` | Age events past 30 days, link 2 events to active alert, run retention. | Unlinked events purged; evidence events strictly preserved. | Only unlinked events deleted; evidence rows intact. | **PASS** |
| **STO-05** | `test_alert_persistence_evidence_and_lifecycle` | Insert alert, transition status from New -> Acknowledged -> Resolved. | Transitions persisted; audit history records actor and timestamp. | Full lifecycle persisted with immutable audit trail. | **PASS** |
| **STO-06** | `test_file_backed_database_reopening` | Create database on disk, write records, close pool, reopen pool. | Data remains intact; schema versions verified; no corruption. | Database successfully reopened and verified. | **PASS** |

### 1.4 Frontend React & IPC Interface (`ui`)
| Test ID | Test Target | Steps | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **UI-01** | `renders app layout and navigation links` | Mount `App.tsx` inside jsdom with mocked Tauri commands. | Navigation links, brand banner, and default Overview page render. | Overview KPI cards, sidebar, and header rendered. | **PASS** |
| **UI-02** | `navigates to network events page` | Click "Network Events" navigation button. | Displays Network Events table with search bar and filter controls. | Events table rendered with pagination controls. | **PASS** |
| **UI-03** | `navigates to security alerts page` | Click "Security Alerts" navigation button. | Displays Security Alerts list with severity badges and status filters. | Alerts table rendered with action buttons. | **PASS** |
| **UI-04** | `navigates to detection rules configuration` | Click "Detection Rules" navigation button. | Displays NET-001 and NET-002 rule configuration cards with sliders. | Rules page rendered with threshold controls. | **PASS** |
| **UI-05** | `navigates to telemetry page` | Click "Telemetry" navigation button. | Displays collection status, polling frequency, and start/stop controls. | Telemetry controls and live metrics rendered. | **PASS** |
| **UI-06** | `navigates to audit history page` | Click "Audit History" navigation button. | Displays audit log timeline with actor, action, and target IDs. | Audit history rendered with pagination. | **PASS** |
| **UI-07** | `navigates to settings and renders about section` | Click "Settings" navigation button. | Displays database paths, retention settings, and About SentinelX card. | Settings rendered including About section with v1.0.0. | **PASS** |

### 1.5 End-to-End Release Packaging & Execution
| Test ID | Test Target | Steps | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **E2E-01**| `release_executable_help` | Run `target\release\sentinel-app.exe --help`. | Displays CLI options and usage without crashing. | Help text printed successfully; exit code 0. | **PASS** |
| **E2E-02**| `release_cli_telemetry_cycle` | Run `sentinel-app.exe --cli --mock --max-cycles 1 --db target\test.db`. | Initializes database, applies migrations, processes batch, cleans up. | 1 cycle executed, 15 events saved, exit code 0. | **PASS** |
| **E2E-03**| `nsis_installer_bundling` | Run `npx --prefix ui tauri build --bundles nsis`. | Produces `SentinelX_1.0.0_x64-setup.exe` in `target\release\bundle\nsis\`. | Installer generated (3.78 MB). | **PASS** |
| **E2E-04**| `checksum_generation` | Compute SHA-256 hash of installer and binary. | Produces deterministic hashes saved to `SHA256SUMS.txt`. | Hashes generated and verified. | **PASS** |
