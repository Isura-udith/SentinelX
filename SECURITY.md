# Security Policy: SentinelX

## Defensive Scope & Operational Philosophy

SentinelX is developed strictly as a defensive telemetry monitoring, persistent auditing, and analytical detection platform.

### Non-Interference Guarantee
SentinelX detection rules, storage engines, and schedulers operate in an observational capacity. The software:
- **Does not execute active network countermeasures**, IP bans, socket resets, or process terminations.
- **Does not conduct offensive probing**, network scanning, port enumeration, or remote exploits.
- **Does not require elevated administrative privileges** for standard TCP table enumeration or local SQLite persistence.
- **Does not capture packet payloads**, decrypt TLS traffic, or intercept user credentials.

Alerts emitted by SentinelX represent evidence-backed hypotheses for human security analyst review or integration into security operations center (SOC) triage queues.

---

## Database Security & Data Protection (Phase 3)

### 1. SQL Injection Prevention
- All database operations in `sentinel-storage` utilize **parameterized SQL queries** via `sqlx`.
- Raw string interpolation into SQL statements is strictly prohibited.
- User input (such as CLI filter parameters) is strictly validated prior to query execution.

### 2. Local Filesystem Permissions & Least Privilege
- SentinelX stores connection records, alerts, and audit entries in a local SQLite file (`sentinelx.db`).
- On Windows systems, the directory (`%LOCALAPPDATA%\SentinelX`) should be secured with NTFS Access Control Lists (ACLs) granting access only to the executing user account and `SYSTEM`.
- The application never runs with broader filesystem or network listening permissions than required.

### 3. Sensitive Data Handling
- SentinelX records only connection metadata: source/destination IP addresses, ports, protocol, process ID, and TCP state.
- It **never** captures, logs, or stores packet payload data, HTTP headers, authentication tokens, or keystrokes.
- The `metadata_json` field enforces a strict byte size limit (max 4,096 bytes) and validated JSON structure.

### 4. Audit Trail Integrity
- Analyst triage actions (acknowledging an alert, resolving an alert) and retention runs are immutably appended to the `audit_log` table.
- Audit logs maintain a minimum 90-day retention guarantee and cannot be deleted by standard alert resolution workflows.

### 5. Migration Safety
- Schema migrations are embedded at compile time using `sqlx::migrate!()`.
- Migrations execute within discrete database transactions. If a migration step encounters an error, the transaction rolls back cleanly.
- The application **never** attempts destructive database resets or deletes user databases upon startup failure.

---

## Supported Environments

| Phase | Platform | Status | Privileges Required |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Windows 11 / Cross-platform synthetic verification | Complete | None (Standard user) |
| **Phase 2** | Windows 11 (64-bit) TCP snapshot collector | Complete | None (Standard user) |
| **Phase 3 (Current)** | Windows 11 (64-bit) / SQLite persistence & stateful detection | Complete | None (Standard user) |
| **Phase 4 (Planned)** | Windows 11 ETW event-driven collection & desktop UI | Planned | Administrator (ETW session creation) |

---

## Current Security Limitations

1. **No External Security Audit**: SentinelX is an educational systems engineering and defensive architecture portfolio project. It has not undergone an independent third-party cybersecurity audit or formal certification.
2. **Snapshot Sampling Heuristics**: As documented in `docs/detection-rules.md`, point-in-time TCP snapshot polling resamples long-lived connections. Detections reflect observation volume rather than verified connection initiation handshakes.
3. **Local Encryption**: SQLite database files are not encrypted at rest by default. Users requiring encryption-at-rest should deploy SentinelX on BitLocker-encrypted NTFS volumes.
4. **Local Execution Context**: SentinelX operates as a local endpoint process and does not expose unauthenticated network listening sockets.

---

## Vulnerability Reporting

If you identify a security vulnerability, memory safety defect, or invariant bypass in SentinelX:

1. **Responsible Disclosure**: Please submit a private issue or advisory report through the repository hosting interface (e.g., GitHub Security Advisories).
2. **Details to Include**:
   - Detailed description of the vulnerability and affected crate/module.
   - Minimal proof-of-concept (PoC) code or synthetic event payload.
   - Potential impact on analytical integrity, denial-of-service, or data corruption.
3. **Response Protocol**: Security issues will be triaged and addressed with priority fixes in a designated patch release.
