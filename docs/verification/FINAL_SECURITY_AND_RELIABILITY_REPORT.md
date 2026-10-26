# SentinelX Final Security and Reliability Report

## 1. Executive Summary

SentinelX is an offline, defensive desktop cybersecurity monitoring platform engineered in Rust (2024 edition) and Tauri 2.0 with a React 19 frontend. The software passively samples active Windows TCP connection tables using the native Windows IP Helper API (`GetExtendedTcpTable`), normalizes observations into structured network events, evaluates them against in-memory sliding window detection rules (e.g., NET-001 Port-Scan-Like Activity, NET-002 High-Volume Connection Burst), and securely persists state into an embedded SQLite database operating in Write-Ahead Logging (WAL) mode.

This report documents the security posture, memory safety boundaries, Windows privilege containment, FFI integrity, and reliability controls of the production release candidate.

---

## 2. Windows Privilege Model & Elevation Analysis

| Criterion | Evaluation | Verification Result |
| :--- | :--- | :--- |
| **Execution Elevation** | Standard non-elevated user (`Medium Integrity Level`). Does **not** require or prompt for UAC administrator privileges. | **PASS** |
| **Installer Elevation** | NSIS package configured with `installMode: "currentUser"`. Installs directly to `%LOCALAPPDATA%\Programs\SentinelX`. | **PASS** |
| **System Service Installation** | Zero background Windows services registered. SentinelX executes strictly as a standard desktop user process. | **PASS** |
| **Kernel Driver Utilization** | Zero filter drivers (`.sys`), NDIS drivers, or kernel modules required or utilized. | **PASS** |
| **Privilege Escalation Surface** | Windows IP Helper snapshot (`GetExtendedTcpTable`) executes cleanly within standard user permissions, exposing standard TCP socket endpoints and owning PID for the user's session without requiring `SeDebugPrivilege`. | **PASS** |

---

## 3. Native Windows FFI & Memory Safety

### 3.1 `GetExtendedTcpTable` Implementation Safety
The native collector in `sentinel-collector/src/windows_tcp.rs` interfaces directly with `iphlpapi.dll` using safe Rust abstractions:
- **Dynamic Allocation Sizing:** The collector queries buffer dimensions by issuing an initial call with zero length or inspecting the returned `dwSize`. Memory buffers (`Vec<u8>`) are allocated dynamically to fit the table.
- **Buffer Growth & Race Handling:** Sockets can be opened/closed concurrently by other processes. If `ERROR_INSUFFICIENT_BUFFER` is returned, the allocation logic increases buffer capacity and retries up to 3 times before returning a structured error.
- **Pointer & Slice Boundaries:** Raw pointer conversions enforce alignment checks and calculate offsets strictly based on row structs (`MIB_TCPROW_OWNER_PID` for IPv4, `MIB_TCP6ROW_OWNER_PID` for IPv6). Boundary checks ensure the loop terminates before pointer exceeds allocated byte slice bounds.
- **Leak Elimination:** All allocated buffers are managed by standard Rust RAII `Vec<u8>` containers; early returns on error automatically free buffer memory.

---

## 4. Local-First Privacy & Telemetry Containment

SentinelX adheres to strict privacy and defensive principles:
- **Zero Cloud Egress:** There are no outbound HTTP clients, telemetry SDKs, crash report uploaders, or analytics endpoints in either the Rust backend or TypeScript frontend.
- **Local Persistence Only:** All network events, alert details, detection rule configurations, and audit trails remain strictly inside the local SQLite database at `%LOCALAPPDATA%\com.sentinelx.desktop\sentinelx.db`.
- **No Payload Inspection:** SentinelX inspects metadata only (local IP, local port, remote IP, remote port, process ID, TCP state). It does not perform packet sniffing, payload decryption, deep packet inspection (DPI), or SSL/TLS interception.
- **Defensive Containment:** No active network disruption, socket reset injection, host isolation, firewall rule injection, or process termination capabilities are present in the codebase.

---

## 5. Storage Security & Injection Resistance

- **Parameterized Queries:** All SQL operations in `sentinel-storage` utilize compile-time checked and parameterized queries via `sqlx`. User input (such as search queries, IP addresses, pagination offsets, and rule configuration updates) is bound via parameters (`?`), eliminating SQL injection risks.
- **Foreign Key Integrity:** Database initialization executes `PRAGMA foreign_keys = ON;` and `PRAGMA journal_mode = WAL;`. Orphaned records and dangling alert-evidence associations are structurally prevented by database constraints.
- **Deterministic Retention Management:** Storage enforces configurable retention windows (default 30 days for network events, 90 days for audit records). Bounded deletion transactions prevent unbounded lock contention or table fragmentation.
- **Database File Protection:** Default database paths reside within authenticated user profile directories with standard NTFS Access Control Lists (ACLs) preventing unauthorized cross-user access.

---

## 6. Tauri IPC & Content Security Policy (CSP)

### 6.1 Capability Isolation
Frontend-to-backend communication uses Tauri 2.0 type-safe IPC. Unrestricted native plugins (such as arbitrary filesystem access, external HTTP fetch, or shell process spawning) are omitted.
- Registered commands are explicitly enumerated in `crates/sentinel-app/src/main.rs`.
- All commands undergo strict parameter parsing and boundary validation in `commands.rs`.

### 6.2 Frontend Content Security Policy
The application window enforces a strict Content Security Policy defined in `tauri.conf.json`:
```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'
```
- Remote scripts, inline script evaluations, and external web resource fetching are blocked.
- External documentation links (`GitHub`, `Docs`) in `SettingsPage.tsx` open safely via the OS default browser without granting web context access to Tauri IPC APIs.

---

## 7. Reliability, Resource Limits & Shutdown

- **Collector Thread Isolation:** The telemetry polling loop executes asynchronously using Tokio timers. The underlying Windows API call runs inside `tokio::task::spawn_blocking` to prevent blocking the async runtime executor threads.
- **Controlled Error States:** Telemetry collection errors update an atomic lifecycle status (`CollectorDegraded` or `CollectorFailed`) without crashing the application or returning fabricated zero-counts.
- **Bounded In-Memory Engines:** Detection rules implement rolling time windows and explicit maximum evidence capacities (`max_evidence_ids_per_alert`), preventing in-memory memory exhaustion during sustained high-connection bursts.
- **Graceful Shutdown:** The desktop application listens for close events and signals, gracefully drains background ingestion pipelines, executes final database commits, and releases WAL file locks before terminating.

---

## 8. Summary Security Finding Matrix

| Vulnerability Category | Status | Mitigating Architecture |
| :--- | :--- | :--- |
| **SQL Injection** | **Resolved / Immune** | Parameterized queries via `sqlx` with zero dynamic SQL concatenation. |
| **Cross-Site Scripting (XSS)** | **Resolved / Immune** | React 19 JSX sanitization + strict Tauri CSP preventing external script execution. |
| **Privilege Escalation** | **Resolved / Immune** | Non-elevated standard user execution model (`currentUser` NSIS installer). |
| **Memory Corruption (FFI)** | **Verified Safe** | Bounds-checked slices, safe wrapper over `GetExtendedTcpTable`, RAII buffers. |
| **Information Disclosure** | **Verified Safe** | Strict local-only database storage; zero cloud analytics or outbound telemetry. |
| **Denial of Service (Storage)** | **Mitigated** | Configurable retention purging + sliding window in-memory state pruning. |

---

**Report Certification:**
This security review confirms that SentinelX v1.0.0 meets conservative defensive cybersecurity standards for non-elevated, privacy-preserving desktop endpoint monitoring on Windows 11.
