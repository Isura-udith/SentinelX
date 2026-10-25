# SentinelX Final Application Security Review

**Evaluation Target:** SentinelX v1.0.0 Release Candidate  
**Audit Date:** 2026-10-25  
**Reviewers:** Senior Rust & Application Security Engineering Team  
**Scope:** Architecture, Privilege Model, Data Protection, Desktop FFI/IPC, Rust Memory Safety, and Residual Risk.

---

## 1. Application Privilege Model

| Aspect | Architectural Evaluation | Compliance Status |
| :--- | :--- | :--- |
| **Execution Context** | Runs as standard, unprivileged Windows user (`Medium Integrity Level`). | **PASS** |
| **Administrative Elevation**| Does not request `requireAdministrator` in manifest; no UAC prompts on start. | **PASS** |
| **Kernel / System Driver** | No kernel driver (`.sys`) or Windows service installed. | **PASS** |
| **Installation Directory** | Per-user setup installed to `%LOCALAPPDATA%\Programs\SentinelX`. | **PASS** |
| **Writable Data Directory**| Dedicated user data directory at `%LOCALAPPDATA%\SentinelX`. No writes to `Program Files`. | **PASS** |

---

## 2. Telemetry Collection Safety

1. **Read-Only Inspection:**
   - Network telemetry queries the Windows IP Helper table via native Windows API `GetExtendedTcpTable`.
   - The API is strictly non-intrusive and read-only.
2. **No Active Network Interference:**
   - SentinelX does **not** perform active network scanning (e.g., SYN sweeps or banner grabbing).
   - SentinelX does **not** filter, divert, or block TCP connections.
   - SentinelX does **not** terminate or kill processes.
3. **No Packet Payload Capture:**
   - Only socket metadata is observed: local IP/port, remote IP/port, TCP state, PID, and timestamp.
   - Application layer payloads (HTTP headers, credentials, passwords, message bodies) are never captured, handled, or stored.
4. **Scope Disclosure:**
   - The application explicitly discloses in the UI About section and documentation that TCP snapshots cannot capture ephemeral connections that open and close between polling intervals.

---

## 3. Data Protection & Storage Security

1. **Local-First Zero Cloud:**
   - 100% of telemetry, detection state, and alert records remain stored on the local disk.
   - No external telemetry beacons, remote analytics, or cloud upload channels exist.
2. **Parameterized Database Queries:**
   - All SQLite queries are executed using `sqlx` compile-time and runtime query binding with parameterized placeholders (`?`). No SQL string concatenation exists in the codebase.
3. **Transactional Integrity & Crash Resilience:**
   - Database operates with `PRAGMA journal_mode = WAL` and `PRAGMA synchronous = NORMAL`.
   - Foreign key cascading and constraints (`PRAGMA foreign_keys = ON`) protect referential integrity between events, alerts, and evidence associations.
4. **Evidence-Preserving Retention Enforcement:**
   - Automated retention cleanup purges aged events while strictly preserving any event marked as supporting evidence for an existing security alert.
5. **No Secrets Logging:**
   - Tracing logs emit structured diagnostic context without user passwords, sensitive tokens, or arbitrary memory dumps.

---

## 4. Desktop Framework & IPC Security (Tauri 2)

1. **Capabilities & Scopes:**
   - Tauri capabilities configuration (`crates/sentinel-app/capabilities/default.json`) restricts frontend permissions to `core:default`.
   - Arbitrary shell execution (`shell:allow-execute`), filesystem manipulation (`fs:allow-read/write`), and external webview browsing are disabled.
2. **Content Security Policy (CSP):**
   - Configured in `tauri.conf.json`:
     ```text
     default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'
     ```
   - Disallows external script injection, remote JavaScript loading, and arbitrary network fetches from the frontend renderer.
3. **IPC Input Validation:**
   - All frontend-to-Rust command inputs (alert IDs, pagination limits, filter criteria, rule parameters) are validated via strongly typed Rust DTOs and bounds checks before execution.
   - Paging limits are capped (e.g., maximum 200 items per request) to prevent denial-of-service via excessive memory allocation.

---

## 5. Rust Safety & Windows FFI Review

1. **Unsafe FFI Isolation:**
   - Direct FFI calls to `GetExtendedTcpTable` are strictly confined to `crates/sentinel-collector/src/windows_tcp.rs`.
   - All other workspace crates (`sentinel-core`, `sentinel-detection`, `sentinel-storage`, `sentinel-app`) enforce `#![deny(unsafe_code)]`.
2. **FFI Buffer Safety:**
   - Buffer size calculation handles `ERROR_INSUFFICIENT_BUFFER` dynamically in a bounded retry loop (max 5 iterations) to guard against concurrent table growth.
   - Pointer offsets and row counts (`dwNumEntries`) are bound to allocated vector capacities before memory dereferencing.
3. **Safe Memory & Error Handling:**
   - Recoverable runtime errors return explicit `Result<T, E>` types. No unhandled `panic!` or unbounded `unwrap()` calls exist on operational paths.

---

## 6. Residual Risk Assessment

While SentinelX adheres to strict defensive engineering standards, the following residual risks and operational boundaries are documented:

1. **Snapshot Polling Blindspot:**
   - Attackers using high-frequency ephemeral connections (e.g., socket open, payload send, socket close within <10ms) may evade detection between 1,000ms polling cycles.
   - *Mitigation for future releases:* Planned integration with Event Tracing for Windows (ETW) kernel provider `Microsoft-Windows-Kernel-Network`.
2. **Code Signing SmartScreen Warning:**
   - Until signed with a trusted commercial Microsoft Authenticode certificate, Windows Defender SmartScreen will alert users on first launch.
   - *Mitigation:* Comprehensive checksum verification guide and documentation provided in `docs/user/INSTALLATION_AND_UNINSTALLATION.md`.
3. **Host-Level Compromise:**
   - Because SentinelX runs in user space, malware running with `Administrator` or `SYSTEM` privileges on the same host could tamper with local SQLite files or terminate the monitoring process.
   - *Design Boundary:* SentinelX is a defensive monitoring assistant for authorized operators, not an immutable anti-tamper rootkit.
