# Security Policy: SentinelX

## Defensive Scope & Operational Philosophy

SentinelX is developed strictly as a defensive host telemetry monitoring, persistent auditing, and analytical detection platform for Windows 11.

### Non-Interference Guarantee
SentinelX detection rules, storage engines, and schedulers operate in an observational capacity. The software:
- **Does not execute active network countermeasures**, IP bans, socket resets, or process terminations.
- **Does not conduct offensive probing**, network scanning, port enumeration, or remote exploits.
- **Does not require elevated administrative privileges** for standard TCP table enumeration or local SQLite persistence.
- **Does not capture packet payloads**, decrypt TLS traffic, or intercept user credentials.

Alerts emitted by SentinelX represent evidence-backed hypotheses for human security analyst review or integration into security operations center (SOC) triage queues.

---

## Supported Versions

| Version | Supported | Description | Privileges Required |
| :--- | :--- | :--- | :--- |
| **0.2.x (Phase 5 Release Candidate)** | :white_check_mark: **Yes** | Hardened Windows 11 desktop app with Tauri 2, SQLite, and analytical detection rules | None (Standard user) |
| **0.1.x** | :x: No | Historical development milestones | None (Standard user) |

---

## Defensive Architecture & Security Controls (Phase 5)

### 1. SQL Injection Prevention & Parameterization
- 100% of database operations in `sentinel-storage` utilize **parameterized SQL queries** via `sqlx`.
- Dynamic string concatenation for SQL statements is strictly prohibited across the codebase.
- User input (such as CLI and UI filter parameters) is validated prior to query execution.

### 2. Local Filesystem Permissions & Least Privilege
- SentinelX stores connection records, alerts, and audit entries in a local SQLite file (`sentinelx.db`).
- On Windows systems, the directory (`%LOCALAPPDATA%\SentinelX`) is secured with Windows NTFS Discretionary Access Control Lists (DACLs) granting access only to the executing user account and `SYSTEM`.
- The application executes as a standard user process and never prompts for User Account Control (UAC) elevation.

### 3. Tauri 2 Desktop & Content Security Policy (CSP)
- The desktop webview enforces a strict Content Security Policy denying remote origins, unsafe inline scripts, and external network navigation.
- Desktop capabilities (`capabilities/default.json`) are restricted to `core:default` and `windows: ["main"]`. Arbitrary shell execution and unrestricted filesystem access plugins are disabled.
- Frontend input parameters (search strings, notes, rule IDs, limits, offsets) are independently validated in the Rust backend before querying storage.

### 4. Memory Safety & Unsafe Containment
- Unsafe Rust code is forbidden across `sentinel-core`, `sentinel-detection`, and `sentinel-app`.
- Unsafe code is strictly quarantined to Windows C-FFI calls in `sentinel-collector::windows_tcp`. Every unsafe block is validated with an explicit `// SAFETY:` rationale, unaligned pointer reading (`std::ptr::read_unaligned`), and record count upper bounds (`MAX_SNAPSHOT_RECORDS = 50,000`).

### 5. Sensitive Data Handling & Error Sanitization
- SentinelX records connection metadata: source/destination IP addresses, ports, protocol, process ID, and TCP state.
- It **never** captures, logs, or stores packet payload data, HTTP headers, authentication tokens, or keystrokes.
- Internal database paths, SQL query fragments, and OS connection details are suppressed from frontend error messages and logged exclusively to backend tracing facilities.

### 6. Audit Trail Integrity
- Analyst triage actions (acknowledging an alert, resolving an alert, rule configuration updates) and retention runs are immutably appended to the `audit_log` table.
- Audit entries enforce length limits (`MAX_AUDIT_*`), validated JSON structures, and clock skew boundaries.

### 7. Migration Safety
- Schema migrations are embedded at compile time using `sqlx::migrate!()`.
- Migrations execute within discrete database transactions. If a migration step encounters an error, the transaction rolls back cleanly.
- The application **never** attempts destructive database resets or silently deletes user databases upon startup failure.

---

## Current Security Limitations

1. **Local Same-User Tampering**: SentinelX operates as a standard user-mode process. Any other process running under the identical Windows user security context has OS-level rights to read or modify `%LOCALAPPDATA%\SentinelX\sentinelx.db`. Hardware-backed encryption at rest (e.g., DPAPI-wrapped SQLCipher) is planned for future enterprise releases.
2. **Snapshot Sampling Heuristics**: Point-in-time TCP snapshot polling resamples long-lived connections. Detections reflect observation volume and state within rolling time windows rather than verified initial SYN handshakes.
3. **No Packet Payload Inspection**: Telemetry collection via `GetExtendedTcpTable` does not inspect packet contents or decrypt TLS encrypted streams. Detections are based strictly on connection metadata.
4. **Unsigned Release Candidate Binaries**: Release artifacts for this phase are unsigned. Windows SmartScreen may present an unknown publisher warning upon installation.

---

## Vulnerability Reporting

If you identify a security vulnerability, memory safety defect, or invariant bypass in SentinelX:

1. **Responsible Disclosure**: Please report security vulnerabilities privately via the repository hosting security advisory interface (e.g., GitHub Security Advisories).
2. **Details to Include**:
   - Detailed description of the vulnerability and affected crate/module.
   - Minimal proof-of-concept (PoC) code or synthetic event payload.
   - Potential impact on analytical integrity, denial-of-service, or data corruption.
3. **Response Protocol**: Security issues will be triaged and addressed with priority fixes in a designated patch release.
