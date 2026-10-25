# SentinelX Release Notes: Version 1.0.0 (Release Candidate)

**Release Tag:** `v1.0.0`  
**Target Platform:** Windows 11 (x86_64)  
**Release Date:** 2026-10-25  
**Installer Artifact:** `SentinelX_1.0.0_x64-setup.exe` (SHA-256: `63A86984E27B419F28A5AC4EECDA77B59EE189222BB3E186BA541026F2B81BE0`)  

---

## 1. Overview

SentinelX v1.0.0 represents the culmination of Weeks 1–16 of development. It delivers an educational, local-first defensive security monitoring desktop application designed specifically for Windows 11. It provides non-intrusive host telemetry, real-time threat detection, local SQLite persistence with WAL mode, and a reactive desktop SOC dashboard.

---

## 2. Key Implemented Features

### 2.1 Packaging & Release Engineering (Phase 6)
- **Windows NSIS Installer:** Created native Windows setup package (`SentinelX_1.0.0_x64-setup.exe`) configured for `currentUser` (per-user) installation without requiring administrative privileges.
- **Unified Versioning:** Synchronized project version across workspace `Cargo.toml`, `tauri.conf.json`, `package.json`, and frontend UI to `1.0.0`.
- **Automated Verification Pipeline:** Implemented `scripts/verify-release.ps1` automating Rust formatting, Clippy analysis, workspace tests, frontend checks, asset building, and packaging.
- **CI/CD Automation:** Hardened `.github/workflows/ci.yml` and added `.github/workflows/release.yml` with pinned third-party actions and automated release artifact staging.
- **Software Bill of Materials (SBOM):** Generated CycloneDX v1.5 JSON SBOM (`docs/release/SBOM.json`) detailing all runtime dependencies and licenses.

### 2.2 Telemetry & Windows Host Integration
- **Windows IP Helper Collection:** Read-only TCP table inspection via `GetExtendedTcpTable` from `windows-sys`.
- **Byte Order & Socket Normalization:** Full Big-Endian decoding for IPv4, IPv6, and port numbers. Loopback and listening sockets properly classified.
- **Process Attribution:** Captures owning Process ID (PID) for each active socket.
- **Mock Telemetry Mode:** Safe, deterministic in-memory mock collector for demonstration and testing.

### 2.3 Stateful Threat Detection
- **Rule NET-001 (Port-Scan-Like Activity):** Stateful detection tracking distinct destination ports targeted per source IP within a sliding 60-second window (default threshold: 10 ports) with 300-second alert cooldown suppression.
- **Rule NET-002 (Connection Burst Anomaly):** Detects anomalous surges in established connections from a single IP (default threshold: 20 connections in 60s).
- **Runtime Rule Tuning:** Dynamic threshold, window duration, and cooldown configuration persisted in SQLite.

### 2.4 Persistence & Retention
- **Embedded Migrations:** Schema migrations (`0001` through `0003`) compiled directly into the binary via `sqlx::migrate!`.
- **Crash-Resilient Storage:** SQLite configured with WAL mode (`PRAGMA journal_mode = WAL`) and foreign key enforcement.
- **Evidence-Preserving Retention:** Background retention cleans historical events older than 30 days while strictly protecting all events linked as alert evidence.
- **Immutable Audit Logging:** Full audit trail for alert status changes and rule configuration updates.

### 2.5 Desktop Dashboard & User Experience
- **Overview SOC Dashboard:** Real-time KPI summary cards, time-series traffic charts, and alert severity distributions.
- **Alert Triage Lifecycle:** Workflow allowing operators to inspect evidence, Acknowledge alerts, and Resolve incidents with operational notes.
- **Settings & About Section:** Discloses application version, target platform, license, repository links, and defensive boundaries.

---

## 3. Test Suite & Verification Results

| Test Category | Suite / Framework | Total Tests | Result |
| :--- | :--- | :--- | :--- |
| **Rust Unit & Property Tests** | `cargo test --workspace` | 72 tests | **ALL PASSED** |
| **Storage & Integration** | `tests/storage_integration.rs` | 9 tests | **ALL PASSED** |
| **Detection Pipeline** | `tests/detection_pipeline.rs` | 1 test | **ALL PASSED** |
| **Failure Injection** | `tests/failure_injection.rs` | 6 tests | **ALL PASSED** |
| **Frontend Tests** | Vitest (`ui/src/test/app.test.tsx`) | 7 tests | **ALL PASSED** |
| **Frontend Static Analysis** | TypeScript (`tsc --noEmit`), Oxlint | 29 files | **0 Errors, 0 Warnings** |
| **Dependency Security Audit** | `npm audit` | 172 packages | **0 Vulnerabilities** |

---

## 4. Known Limitations & Scope Boundaries

1. **Snapshot Polling Blindspot:** SentinelX inspects the Windows TCP table periodically (default: 1,000ms). Ephemeral connections that complete a full three-way handshake and tear down in <10ms between polling cycles may not be captured.
2. **Read-Only / No Packet Inspection:** SentinelX is a passive metadata monitor. It does not inspect packet payloads, decrypt TLS traffic, or block connections.
3. **SmartScreen Prompt:** As an open-source educational project without an enterprise EV signing certificate, Windows Defender SmartScreen will prompt users on first launch. Verify the SHA-256 hash to confirm authenticity.

---

## 5. Artifact Hashes (SHA-256)

```text
63A86984E27B419F28A5AC4EECDA77B59EE189222BB3E186BA541026F2B81BE0  SentinelX_1.0.0_x64-setup.exe
C0D9DAC824621BAC72D9838AB2C022D7BB327AC70DFD71F25D732DC8C9BF7C5A  sentinel-app.exe
```
