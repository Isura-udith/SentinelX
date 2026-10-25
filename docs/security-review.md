# Security Review Report: SentinelX Phase 5

## 1. Executive Summary

This report documents the security audit, vulnerability analysis, and hardening implementations performed for SentinelX Phase 5 (Security Hardening and Integration). The evaluation encompassed all workspace Rust crates (`sentinel-core`, `sentinel-collector`, `sentinel-detection`, `sentinel-storage`, `sentinel-app`), the Tauri 2 desktop integration layer, and the React 19/TypeScript frontend.

The audit identified multiple security and reliability findings across native Windows API integration, IPC boundaries, database configuration, and frontend state management. All identified critical, high, and medium severity findings have been mitigated and verified through automated tests.

---

## 2. Audit Findings & Remediations Matrix

| Finding ID | Severity | Component | Description | Status | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **High** | `sentinel-collector` | Potential unbounded native snapshot record count from `GetExtendedTcpTable` | **Remediated** | `MAX_SNAPSHOT_RECORDS = 50,000` bound added; verified in `windows_tcp.rs`. |
| **SEC-02** | **High** | `sentinel-app` | Internal filesystem paths (`AppData`, `sentinelx.db`) and SQL errors leaked to UI | **Remediated** | `AppError` sanitization implemented; path/SQL stripped from UI responses. |
| **SEC-03** | **Medium** | `sentinel-app` | Overly permissive Tauri capability configuration (`windows: ["*"]`) | **Remediated** | Restricted strictly to `windows: ["main"]` in `capabilities/default.json`. |
| **SEC-04** | **Medium** | `sentinel-storage` | Missing validation on `DatabaseConfig` (empty path, null byte injection, zero pool size) | **Remediated** | `DatabaseConfig::validate()` added; tested in `test_database_config_validation_rejections`. |
| **SEC-05** | **Medium** | `sentinel-storage` | Unbounded text and metadata sizes in `AuditEntry` allowing memory bloat | **Remediated** | String and details byte bounds (`MAX_AUDIT_*`) enforced with validation errors. |
| **SEC-06** | **Medium** | `sentinel-storage` | Unbounded notes in alert acknowledge and resolve operations | **Remediated** | Note length clamped to `<= 1024` chars; returns `ValidationError`. |
| **SEC-07** | **Medium** | `sentinel-app` | Unbounded command parameters (search text, IP strings, offsets) | **Remediated** | Input bounds (`search_text <= 256`, `ip <= 64`, `offset <= 1,000,000`) enforced. |
| **SEC-08** | **Medium** | `sentinel-app` | Alert reported as detected even if database persistence/correlation fails | **Remediated** | `process_cycle` in `pipeline.rs` filters alerts by database transaction success. |
| **SEC-09** | **Low** | `sentinel-storage` | Database lock contention under concurrent alert updates | **Remediated** | Bounded exponential retry loop (`upsert_correlated_alert_bounded`) added. |
| **SEC-10** | **Low** | `ui` | Synchronous `setState` in React `useEffect` hooks causing re-render loops | **Remediated** | Refactored all 8 pages to async Promises with unmount cleanup (`ignore` flag). |

---

## 3. Deep-Dive Component Reviews

### 3.1 `sentinel-collector`: Windows API & Unsafe Rust Isolation
- **Code Inspected**: [`crates/sentinel-collector/src/windows_tcp.rs`](file:///d:/SentinelX/crates/sentinel-collector/src/windows_tcp.rs), [`crates/sentinel-collector/src/normalize.rs`](file:///d:/SentinelX/crates/sentinel-collector/src/normalize.rs).
- **Security Assessment**:
  - Unsafe code is strictly quarantined to `windows_tcp.rs` for calling Microsoft `GetExtendedTcpTable` via C-FFI.
  - Every unsafe block contains an explicit `// SAFETY:` comment documenting pointer validity, buffer capacity, unaligned memory reading (`std::ptr::read_unaligned`), and alignment immunity.
  - Added `MAX_SNAPSHOT_RECORDS = 50,000` upper bound check to prevent integer overflow or runaway allocations in the event of corrupt kernel table headers.
  - Network byte order conversions for IPv4, IPv6, and TCP port numbers (`u16::from_be`) are verified with round-trip property tests.
  - Standard user execution verified: application does not request elevation, does not open invasive process handles, and does not require kernel filter drivers.

### 3.2 `sentinel-storage`: SQLite Security, Transactions & Audit Integrity
- **Code Inspected**: [`crates/sentinel-storage/src/database.rs`](file:///d:/SentinelX/crates/sentinel-storage/src/database.rs), [`crates/sentinel-storage/src/events.rs`](file:///d:/SentinelX/crates/sentinel-storage/src/events.rs), [`crates/sentinel-storage/src/alerts.rs`](file:///d:/SentinelX/crates/sentinel-storage/src/alerts.rs), [`crates/sentinel-storage/src/audit.rs`](file:///d:/SentinelX/crates/sentinel-storage/src/audit.rs), [`crates/sentinel-storage/src/retention.rs`](file:///d:/SentinelX/crates/sentinel-storage/src/retention.rs).
- **Security Assessment**:
  - **SQL Injection**: 100% of SQL queries use parameterized arguments (`?1`, `?2`). No string formatting (`format!`) is used to construct queries.
  - **Referential Integrity**: `PRAGMA foreign_keys = ON;` is enforced on all SQLite connections.
  - **Concurrency & WAL Mode**: `PRAGMA journal_mode = WAL;` and `PRAGMA busy_timeout = 5000;` prevent table lock starvation under concurrent reads and writes.
  - **Retention Hardening**: The retention engine preserves all historical network events referenced by security alerts via foreign key checks and inner joins, ensuring evidence integrity is never compromised during routine log pruning.
  - **Path Safety**: Added `DatabaseConfig::validate()` to reject empty paths, null bytes (`\0`), and zero pool sizes.

### 3.3 `sentinel-app`: Tauri IPC Boundary & Error Sanitization
- **Code Inspected**: [`crates/sentinel-app/src/commands.rs`](file:///d:/SentinelX/crates/sentinel-app/src/commands.rs), [`crates/sentinel-app/src/errors.rs`](file:///d:/SentinelX/crates/sentinel-app/src/errors.rs), [`crates/sentinel-app/capabilities/default.json`](file:///d:/SentinelX/crates/sentinel-app/capabilities/default.json).
- **Security Assessment**:
  - **Input Validation**: All incoming Tauri command arguments are validated prior to database execution:
    - Search queries: capped at 256 characters.
    - Notes: capped at 1024 characters.
    - Limits: clamped to `1..=500`.
    - Offsets: bounded to `0..=1,000,000`.
    - Rule IDs: validated against allowlist (`NET-001`, `NET-002`).
    - UI Themes: validated against allowlist (`dark`, `light`, `system`).
    - Log Verbosity: validated against allowlist (`trace`, `debug`, `info`, `warn`, `error`).
  - **Error Sanitization**: `AppError` maps internal storage errors to user-safe strings:
    - Raw filesystem paths (e.g., `C:\Users\...\AppData\Local\SentinelX`) and internal SQLite query snippets are suppressed.
    - Complete error diagnostics are logged via `tracing::error!` for secure administrator inspection.
  - **Tauri Capabilities**:
    - Capabilities file restricted from `"windows": ["*"]` to `"windows": ["main"]`.
    - No plugins for arbitrary shell or filesystem access are enabled.

### 3.4 `sentinel-detection`: Detection Invariants & State Protection
- **Code Inspected**: [`crates/sentinel-detection/src/engine.rs`](file:///d:/SentinelX/crates/sentinel-detection/src/engine.rs), [`crates/sentinel-detection/src/rules/`](file:///d:/SentinelX/crates/sentinel-detection/src/rules/).
- **Security Assessment**:
  - `#[forbid(unsafe_code)]` enforced at crate level.
  - `DetectionEngine` bounds incoming batches to `max_batch_size = 100,000`.
  - Detection rules bound evidence references attached to any single alert to `1,000`.
  - State window expiration automatically purges aged connection buckets, preventing memory leakage.
  - Out-of-order and future clock skew timestamps are handled safely without arithmetic overflow.

### 3.5 `ui`: Frontend Vulnerabilities & Webview Hardening
- **Code Inspected**: React 19 pages and components in `ui/src/`.
- **Security Assessment**:
  - Content Security Policy (CSP) strictly blocks remote script execution, inline scripts, and untrusted network origins.
  - External URL navigation is disabled in webview configuration.
  - Fixed 8 oxlint warnings regarding synchronous `setState` inside `useEffect` across all dashboard pages, preventing state race conditions and UI freezing.
  - Frontend input validation implemented for search inputs, threshold configurations, and pagination controls.

---

## 4. Residual Risks & Accepted Architecture Decisions

1. **Local User Process Tampering**:
   - **Risk**: A malicious executable running under the same Windows user session has OS permission to read or modify `%LOCALAPPDATA%\SentinelX\sentinelx.db`.
   - **Accepted Decision**: SentinelX operates as a user-space monitoring tool. Encrypted-at-rest database storage (e.g., SQLCipher with DPAPI key derivation) or remote hardware-anchored audit streaming is acknowledged as future enhancement scope.
2. **Standard User Telemetry Scope**:
   - **Risk**: Standard user processes can query TCP endpoints and owning PIDs via `GetExtendedTcpTable`, but cannot inspect socket buffers or process memory of system-privileged processes (`SYSTEM`).
   - **Accepted Decision**: By architectural design, SentinelX deliberately avoids installing kernel filter drivers or running as a high-privilege Windows service.

---

## 5. Security Audit Sign-off

- **Rust Security Tooling**: Clippy (`-D warnings`) passed with **0 warnings**.
- **Memory Safety**: Unsafe code verified and isolated to Windows FFI with bounds enforcement.
- **Dependency Audit**: `npm audit` verified with **0 vulnerabilities**.
- **Integration & Failure Tests**: 6 comprehensive failure injection tests passed.
