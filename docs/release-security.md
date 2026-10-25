# Release Security & Verification: SentinelX

## 1. Release Identification & Target Platform

- **Application Name**: SentinelX
- **Version**: `0.2.0` (Phase 5 Release Candidate)
- **Target Platform**: Microsoft Windows 11 (64-bit, `x86_64-pc-windows-msvc`)
- **Execution Mode**: Non-administrative standard user desktop process
- **Release Status**: Hardened Release Candidate (Unsigned Installer)

---

## 2. Build Environment & Toolchain Baselines

| Component | Verified Version | Distribution / Target |
| :--- | :--- | :--- |
| **Rust Compiler (`rustc`)** | `1.99.1 (58cf8f9c3 2026-10-13)` | `x86_64-pc-windows-msvc` |
| **Cargo Package Manager** | `1.99.1 (5f94df478 2026-08-27)` | Workspace root |
| **Node.js Runtime** | `v24.14.0` | Frontend packaging |
| **Node Package Manager (`npm`)** | `11.9.0` | `ui/` dependency resolution |
| **Tauri Framework** | `2.x` (`tauri = "2"`, `tauri-build = "2"`) | Desktop application wrapper |
| **Target Operating System** | Microsoft Windows 11 (x64) | Tested on native Windows 11 |

---

## 3. Supply-Chain & Dependency Audit Status

### 3.1 Rust Crates
- **Lockfile Policy**: `Cargo.lock` is committed to the repository for deterministic, reproducible builds.
- **Unsafe Policy**: Restricted to `sentinel-collector::windows_tcp`. Forbidden in `sentinel-core` and `sentinel-detection`.
- **Crate Tree**: Minimal dependency footprint avoiding unmaintained or deprecated crates.

### 3.2 Frontend Packages
- **Lockfile Policy**: `ui/package-lock.json` is committed to the repository.
- **npm Audit Execution**:
  ```bash
  npm audit
  ```
  - **Result**: `found 0 vulnerabilities` across all production and development dependencies.

---

## 4. Verification Suite Results

| Test Category | Command | Target / Suite | Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Code Formatting** | `cargo fmt --all -- --check` | Entire Rust workspace | 0 diffs | **PASSED** |
| **Static Analysis / Lint** | `cargo clippy --workspace --all-targets -- -D warnings` | All 5 crates & integration tests | 0 warnings, 0 errors | **PASSED** |
| **Rust Test Suite** | `cargo test --workspace` | Unit, property, and integration tests | 70 passed; 0 failed | **PASSED** |
| **Failure Injection Suite** | `cargo test --test failure_injection` | 6 failure scenarios | 6 passed; 0 failed | **PASSED** |
| **Performance Benchmark** | `cargo test --test benchmark_measurements` | Synthetic 5k event workload | Verified all targets | **PASSED** |
| **Frontend Type Checking** | `npm run typecheck` | TypeScript compiler (`tsc --noEmit`) | 0 type errors | **PASSED** |
| **Frontend Linter** | `npm run lint` | Oxlint (29 files, 116 rules) | 0 warnings, 0 errors | **PASSED** |
| **Frontend Unit Tests** | `npm test` | Vitest (`ui/src/test/app.test.tsx`) | 7 passed; 0 failed | **PASSED** |

---

## 5. Tauri Desktop Capabilities & Content Security Policy

### 5.1 Capability Minimization
The Tauri 2 capability manifest (`crates/sentinel-app/capabilities/default.json`) strictly restricts application permissions:
- **Exposed Windows**: Limited to `["main"]`.
- **Plugin Access**: Arbitrary filesystem plugins (`tauri-plugin-fs`) and process spawning plugins (`tauri-plugin-shell`) are **not** bundled.
- **Exposed Commands**: Only explicitly typed backend commands declared in `main.rs` are exposed:
  - `get_dashboard_summary`
  - `query_network_events`
  - `query_security_alerts`
  - `get_security_alert_details`
  - `acknowledge_security_alert`
  - `resolve_security_alert`
  - `get_alert_evidence`
  - `get_detection_rule_configs`
  - `update_detection_rule_config`
  - `query_audit_entries`
  - `get_app_settings`
  - `update_app_settings`
  - `start_telemetry`
  - `stop_telemetry`
  - `get_telemetry_status`

### 5.2 Content Security Policy (CSP)
The webview enforces a restrictive CSP header:
```http
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'
```
- **Remote Origins**: All remote origins are denied.
- **External Navigation**: Arbitrary external URLs cannot be opened or navigated to inside the webview.

---

## 6. Windows Privilege & Storage Architecture

### 6.1 Least-Privilege Standard User Execution
- **Non-Administrative Execution**: SentinelX runs under the user's standard Windows token without requiring UAC elevation.
- **Windows API Scope**: Utilizes `GetExtendedTcpTable` from `iphlpapi.dll` with `TCP_TABLE_OWNER_PID_ALL`, accessible by standard non-elevated users.
- **No Kernel Drivers**: Avoids custom kernel-mode drivers (`.sys`), eliminating crash (BSOD) risks and kernel attack vectors.
- **No System Modifications**: Does not alter firewall rules, process memory, or network routing tables.

### 6.2 Data Storage Location
- **Directory**: `%LOCALAPPDATA%\SentinelX` (e.g., `C:\Users\<Username>\AppData\Local\SentinelX`).
- **Permissions**: Protected by Windows Discretionary Access Control Lists (DACLs) inherited from the user's profile.
- **Files**:
  - `sentinelx.db`: Embedded SQLite database operating in Write-Ahead Logging (`WAL`) mode with foreign key enforcement.
  - `config.json`: Per-user application configuration file.

---

## 7. Logging & Information Disclosure Safeguards

- **Sanitized Errors**: The backend returns sanitized error messages (`AppError`) to the frontend, preventing the exposure of internal database paths or SQL query structures.
- **Structured Tracing**: Operational logs are emitted via `tracing-subscriber` to local diagnostic log targets.
- **Bounded Inputs**: Search strings are capped at 256 characters; notes are capped at 1024 characters; pagination limits are clamped to `1..=500`.

---

## 8. Code Signing & Release Artifact Disclosures

> [!WARNING]
> **Code Signing Disclosure**:
> Release binaries and Windows installers for this release candidate are **currently unsigned**.
> Because the application is not signed with a Microsoft-trusted Authenticode Code Signing Certificate:
> 1. Windows SmartScreen may present a warning (*"Windows protected your PC - Unknown Publisher"*) when launching the installer.
> 2. No claims are made that antivirus solutions will automatically trust the binary without vendor whitelisting or certificate reputation.
> 3. Production enterprise deployments must sign release artifacts using an organizational Authenticode certificate prior to distribution.

---

## 9. Known Vulnerabilities & Accepted Risks

1. **Local Same-User Tampering**: Any unauthorized software running within the exact same Windows user session has OS-level privileges to read or modify `%LOCALAPPDATA%\SentinelX\sentinelx.db`. Hardware-backed encryption at rest (e.g., DPAPI-wrapped SQLCipher) is planned for future enterprise releases.
2. **Standard User Telemetry Bounds**: Telemetry collection via `GetExtendedTcpTable` does not inspect raw packet payloads or decrypt TLS encrypted streams. Detections are based strictly on connection metadata (IP addresses, ports, PIDs, and timestamp frequencies).
