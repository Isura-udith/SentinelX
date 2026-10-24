# Security Architecture & Privilege Boundaries: SentinelX

## 1. Security Philosophy

SentinelX is designed as a **defensive-only cybersecurity monitoring application**.

Defensive software must not itself introduce security liabilities, increase system attack surfaces, or compromise host stability. SentinelX adheres to strict design principles:
- **Principle of Least Privilege**: Functions under standard user accounts without requesting or requiring elevated privileges.
- **Zero Host Mutation**: Never terminates processes, never alters network routes, never inserts firewall rules, and never alters socket descriptors.
- **No Third-Party Kernel Drivers**: Avoids proprietary or third-party filter drivers (`.sys`), eliminating kernel crash risks (Blue Screen of Death / BSOD) and driver vulnerability exposure.
- **Zero-Panic Defensive Code**: Completely eliminates unhandled panics (`unwrap()`, `expect()`) in production code paths.

---

## 2. Privilege Boundaries & Non-Administrative Operation

### 2.1 Standard User Operation
SentinelX targets Windows 11 using standard user-mode APIs:
- The IP Helper API (`GetExtendedTcpTable`) with `TCP_TABLE_OWNER_PID_ALL` permits standard (non-elevated) processes to enumerate local TCP endpoints and query their owning process IDs (`PID`).
- The application never prompts for User Account Control (UAC) elevation.
- If executed in an environment where specific API operations are restricted by security policy, SentinelX fails gracefully with a typed `CollectorError::NativeApiFailure` rather than attempting privilege escalation.

### 2.2 Process Attribution Scope
The `dwOwningPid` obtained from `GetExtendedTcpTable` indicates the process ID owning the socket at the instant of the snapshot. SentinelX:
- Associates this PID with `NetworkEvent.process_id`.
- Does **not** attempt to open `HANDLE`s to other processes via `OpenProcess` with invasive access masks (`PROCESS_ALL_ACCESS` or `PROCESS_TERMINATE`).
- Does **not** inject DLLs or install hooks into target processes.

---

## 3. Unsafe Rust Isolation & Memory Safety

### 3.1 Unsafe Containment
In SentinelX, the use of `unsafe` Rust is strictly compartmentalized:

| Crate | Unsafe Policy | Justification |
| :--- | :--- | :--- |
| **`sentinel-core`** | `#![forbid(unsafe_code)]` | Domain logic and data structures must remain 100% memory-safe Rust. |
| **`sentinel-detection`** | `#![forbid(unsafe_code)]` | Analytical detection engine and rules must remain 100% memory-safe Rust. |
| **`sentinel-app`** | Workspace default (`deny(unsafe_code)`) | Application orchestration requires no unsafe operations. |
| **`sentinel-collector`** | `#![allow(unsafe_code)]` | Confined exclusively to Windows C-FFI calls in [`windows_tcp.rs`](../crates/sentinel-collector/src/windows_tcp.rs). |

### 3.2 Safety Contracts & FFI Invariants
Every `unsafe` block in [`crates/sentinel-collector/src/windows_tcp.rs`](../crates/sentinel-collector/src/windows_tcp.rs) is preceded by a comprehensive `// SAFETY:` rationale documenting:
1. **Pointer Validity**: Null pointers are only passed where documented by the Windows API to query buffer size.
2. **Buffer Capacity**: Before calling `GetExtendedTcpTable` to write table records, the destination buffer is guaranteed to contain at least `buffer_size` bytes.
3. **Alignment Immunity**: Native table structs are read using `std::ptr::read_unaligned`, preventing misaligned pointer dereference faults.
4. **Boundary Checks**: Buffer sizes are checked using integer overflow-safe arithmetic (`checked_mul`, `checked_add`) against the header size and row count before any rows are parsed.

---

## 4. Input Validation & Defensive Bounding

### 4.1 Configurable Polling Boundaries
To prevent denial-of-service from runaway loops:
- Minimum polling interval is enforced at **100 ms** (`MIN_POLLING_INTERVAL`). Intervals below 100 ms are explicitly rejected during configuration validation.
- Maximum polling interval is bounded at **1 hour** (`MAX_POLLING_INTERVAL`).

### 4.2 Resource Limits & DOS Prevention
- **Batch Size Limits**: `DetectionEngine` rejects batches exceeding `max_batch_size` (default: 100,000) with `BatchSizeExceeded`, protecting host RAM.
- **Evidence Bounding**: Detection rules cap the maximum number of evidence event IDs attached to any single `SecurityAlert` (default: 1,000), preventing alert payload bloat.
- **Port Ranges**: Ports are checked to ensure they reside in `1..=65535`. Port 0 is rejected as an invalid endpoint for active communications.
- **Event Metadata**: Metadata dictionaries are capped at 16 keys with 64-byte key and 256-byte value bounds to prevent memory exhaustion attacks.

---

## 5. Scope & Explicit Exclusions

SentinelX explicitly **does not**:
- Sniff or inspect raw packet payloads.
- Decrypt TLS or SSL sessions.
- Terminate or suspend active processes.
- Modify Windows Defender Firewall rules.
- Route or redirect network packets.
- Perform active port scanning or network probing against external hosts.
- Act as an intrusion prevention system (IPS).

---

## 6. Desktop Application & Tauri 2 Security

### 6.1 Capability Isolation & Least Privilege
SentinelX Desktop enforces Tauri 2 least-privilege capability separation:
- The capability set is locked down to `core:default`.
- Arbitrary shell execution (`tauri-plugin-shell`) is strictly disallowed.
- Arbitrary filesystem access (`tauri-plugin-fs`) is disabled; all file persistence is managed through typed backend commands saving strictly to `%LOCALAPPDATA%\SentinelX`.
- No remote script loading: all assets are compiled and bundled locally.

### 6.2 Strict Content Security Policy (CSP)
The webview enforces a restrictive CSP header:
```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'
```
- Remote navigation is blocked.
- External URLs cannot be navigated to inside the desktop window context.

### 6.3 Local IPC Boundary & Input Sanitization
- All frontend command parameters (IP addresses, port numbers, time ranges, limits) are validated independently on both the frontend and inside Rust command handlers before querying the database.
- Database connection strings, passwords, or host-sensitive environment variables are never transmitted to the frontend webview.
- Errors returned to the UI are mapped to structured, sanitized user-friendly error codes (`AppError`) preventing leakage of internal stack traces.

