# SentinelX Troubleshooting Guide

This guide helps operators diagnose and resolve common issues with telemetry collection, database initialization, Windows SmartScreen, and desktop performance.

---

## 1. Common Issues and Resolutions

### 1.1 Windows SmartScreen Displays "Unknown Publisher"
- **Symptom:** When double-clicking `SentinelX_1.0.0_x64-setup.exe`, Windows Defender SmartScreen displays a blue pop-up: *"Windows protected your PC / Microsoft Defender SmartScreen prevented an unrecognized app from starting."*
- **Cause:** SentinelX is an open-source educational project and is not signed with an enterprise Extended Validation (EV) certificate.
- **Resolution:**
  1. Click **More info**.
  2. Verify the application name displays `SentinelX`.
  3. Click **Run anyway**.
  4. To independently verify file integrity, verify the SHA-256 hash in PowerShell:
     ```powershell
     Get-FileHash .\SentinelX_1.0.0_x64-setup.exe -Algorithm SHA256
     ```
     Compare against the published hash in `docs/release/SBOM_AND_CHECKSUMS.md`.

---

### 1.2 Telemetry Status Shows "Degraded" or Fails to Collect
- **Symptom:** Telemetry status badge displays `Degraded` or `Error`, and no new events appear in the Network Events table.
- **Cause 1: Network Stack Reinitialization:** Host network adapter reset, VPN connection established, or IPv6 disabled mid-session.
- **Cause 2: Collection Paused:** Telemetry polling was stopped via the UI.
- **Resolution:**
  1. Navigate to the **Telemetry** page in the left sidebar.
  2. If the status is `STOPPED`, click **Start Telemetry Collection**.
  3. If an error is shown in the diagnostics card (e.g., `ERROR_INSUFFICIENT_BUFFER` or `WSAEFAULT`), click **Stop Telemetry**, wait 3 seconds, and click **Start Telemetry**.
  4. If running inside a minimal Windows sandbox or virtual machine where TCP tables are inaccessible, switch to **Demonstration Mock Mode** in the Telemetry page.

---

### 1.3 Database Initialization Error on Startup
- **Symptom:** Application fails to launch or displays a fatal error dialog: *"Failed to initialize SQLite persistent storage"*.
- **Cause 1: Insufficient Folder Permissions:** The user profile does not have write access to `%LOCALAPPDATA%\SentinelX\`.
- **Cause 2: Database Lock Contention:** Another instance of SentinelX is already running.
- **Resolution:**
  1. Check Windows Task Manager (`Ctrl + Shift + Esc`). Ensure no background `sentinel-app.exe` processes are lingering.
  2. Test access to the directory in PowerShell:
     ```powershell
     Test-Path "$env:LOCALAPPDATA\SentinelX"
     ```
  3. If corrupted, perform a safe backup of `sentinelx.db` and delete `sentinelx.db-wal` and `sentinelx.db-shm`. (See `docs/user/DATA_BACKUP_AND_RESTORE.md`).

---

### 1.4 Port Scan Alert Does Not Trigger
- **Symptom:** Running a local network scan does not generate a `NET-001` alert.
- **Cause 1: Listening Sockets Excluded:** Local port listeners (`LISTEN`) are intentionally skipped by the normalizer. Only active connection attempts (`SYN_SENT`, `ESTABLISHED`) are evaluated.
- **Cause 2: Cooldown Window Active:** An alert for that source IP already triggered within the past 300 seconds.
- **Cause 3: Threshold Not Reached:** Less than 10 distinct destination ports were contacted within the 60-second window.
- **Resolution:**
  1. Navigate to **Detection Rules**.
  2. Verify that Rule `NET-001` is **Enabled**.
  3. Lower the **Distinct Port Threshold** (e.g., to 5 ports) and **Cooldown Window** (e.g., to 30 seconds) for test scenarios.
  4. Generate traffic targeting distinct ports within the window.

---

### 1.5 UI Freezes or High Memory Usage
- **Symptom:** Dashboard responsiveness degrades after days of continuous operation.
- **Cause:** Huge event accumulation or large query offsets.
- **Resolution:**
  1. Open **Settings** in the sidebar.
  2. Reduce the **Default Event Table Page Size** from 200 to 50 rows.
  3. Set **Event Retention Window** to 7 or 14 days.
  4. Restart SentinelX to trigger a full retention cleanup pass.

---

## 2. Viewing Application Diagnostic Logs

SentinelX logs structured diagnostics using Rust `tracing`:

- **GUI Mode:** Logs are captured in the terminal when launched via command line:
  ```powershell
  & "$env:LOCALAPPDATA\Programs\SentinelX\sentinel-app.exe"
  ```
- **Verbose Debugging:** Set environment variable `RUST_LOG=debug` before starting:
  ```powershell
  $env:RUST_LOG="sentinel_app=debug,sentinel_collector=debug"
  & "$env:LOCALAPPDATA\Programs\SentinelX\sentinel-app.exe"
  ```

---

## 3. Reporting a Bug

If you encounter an unresolvable issue, please submit an issue to the project repository:
- **Repository:** https://github.com/sentinelx/sentinelx/issues
- **Include:**
  - Windows 11 Build Version (`winver`).
  - SentinelX version (`v1.0.0`).
  - Terminal log output or error message text.
  - Steps to reproduce.
