# SentinelX Installation, Upgrade, and Uninstallation Guide

This document describes the Windows 11 lifecycle for SentinelX: fresh installation, in-place version upgrade, uninstallation, data preservation policies, and SmartScreen handling.

---

## 1. Distribution Package Overview

SentinelX is distributed as a self-contained Windows NSIS installer:
- **Installer Name:** `SentinelX_1.0.0_x64-setup.exe`
- **Target Architecture:** 64-bit Windows 11 (x86_64)
- **Install Mode:** Per-User (`currentUser`)
- **Elevation Requirement:** None. Standard Windows user privileges are sufficient. No UAC administrator prompt is triggered during setup.

---

## 2. Fresh Installation

### Step 1: Download & Integrity Verification
1. Download `SentinelX_1.0.0_x64-setup.exe` and `SHA256SUMS.txt` from the official repository release.
2. In PowerShell, compute the installer checksum and compare it to the published hash:
   ```powershell
   Get-FileHash .\SentinelX_1.0.0_x64-setup.exe -Algorithm SHA256
   ```
   *Verified Release Hash:* `63A86984E27B419F28A5AC4EECDA77B59EE189222BB3E186BA541026F2B81BE0`

### Step 2: Running Setup
1. Launch `SentinelX_1.0.0_x64-setup.exe`.
2. **Windows SmartScreen Prompt:**  
   Because SentinelX is an independent open-source educational security project without an enterprise Extended Validation (EV) certificate, Windows SmartScreen may present a blue prompt stating *"Windows protected your PC / Unknown Publisher"*.
   - Click **More info**.
   - Verify the application name displays `SentinelX`.
   - Click **Run anyway**.
3. Follow the installation wizard.
4. The application is installed to the user application directory:
   ```text
   %LOCALAPPDATA%\Programs\SentinelX\
   ```
5. Shortcuts are created in the Start Menu and Desktop.

### Step 3: First Launch & Automatic Database Initialization
1. Launch **SentinelX** from the Start Menu.
2. On first execution, the application automatically:
   - Creates the application data directory: `%LOCALAPPDATA%\SentinelX\`
   - Initializes the SQLite database file: `%LOCALAPPDATA%\SentinelX\sentinelx.db`
   - Configures SQLite PRAGMAs: WAL mode (`PRAGMA journal_mode=WAL`) and foreign key constraints (`PRAGMA foreign_keys=ON`).
   - Executes embedded SQLx migrations:
     - `0001_initial_schema.sql` (events, alerts, audit log, schema version)
     - `0002_detection_indexes.sql` (performance indexes for sliding windows)
     - `0003_rule_config.sql` (detection rule configuration metadata)
   - Creates default configuration: `%LOCALAPPDATA%\SentinelX\settings.json`
3. The dashboard UI loads in Dark Theme displaying real-time telemetry metrics.

---

## 3. Application Data & Directory Separation

SentinelX adheres strictly to Windows desktop filesystem best practices:

| Category | Filesystem Location | Description |
| :--- | :--- | :--- |
| **Application Binaries** | `%LOCALAPPDATA%\Programs\SentinelX\` | `sentinel-app.exe`, DLLs, uninstaller. Read-only during execution. |
| **SQLite Database** | `%LOCALAPPDATA%\SentinelX\sentinelx.db` | Primary persistent storage for normalized network events, security alerts, and rule states. |
| **WAL / SHM Files** | `%LOCALAPPDATA%\SentinelX\sentinelx.db-wal` | Write-Ahead Log journal files for crash-safe concurrency. |
| **User Configuration**| `%LOCALAPPDATA%\SentinelX\settings.json` | Persistent user preferences (theme, polling interval, retention windows). |
| **Audit Log Trail** | Embedded in `sentinelx.db` (`audit_log` table) | Cryptographically verifiable sequence of SOC actions and system events. |

> **Critical Safety Guarantee:** Writable application data is **never** stored inside `Program Files` or the application binary installation directory.

---

## 4. Upgrade Procedure

Upgrading SentinelX to a newer version (e.g., from a test build to v1.0.0) is non-destructive:

1. Close the running SentinelX application.
2. Run the newer version installer (`SentinelX_1.0.0_x64-setup.exe`).
3. The installer replaces the application binaries in `%LOCALAPPDATA%\Programs\SentinelX\`.
4. **Data Preservation:** The existing database (`sentinelx.db`) and user settings (`settings.json`) in `%LOCALAPPDATA%\SentinelX\` are **retained untouched**.
5. On the first launch of the updated version:
   - Any new schema migrations are automatically executed inside an atomic transaction.
   - All historical events, acknowledged/resolved alerts, and audit trails remain accessible.
   - Existing detection rule configurations are preserved.

---

## 5. Uninstallation Procedure

### Standard Removal
1. Open Windows **Settings** > **Apps** > **Installed apps** (or run `Uninstall SentinelX` from the Start Menu).
2. Click **Uninstall**.
3. The uninstaller removes:
   - All program binaries from `%LOCALAPPDATA%\Programs\SentinelX\`.
   - Start Menu and Desktop shortcuts.
   - Windows Add/Remove Programs registry entries.

### Data Preservation Policy
By default, SentinelX **preserves** user security data (`%LOCALAPPDATA%\SentinelX\sentinelx.db` and `settings.json`) upon uninstall. This ensures that accidental uninstallation or version reinstallation does not result in irreversible loss of security incident history or audit evidence.

### Complete Data Purge (Manual)
If you wish to completely wipe all security history, alerts, and settings from the computer after uninstallation:
1. Ensure SentinelX is uninstalled.
2. Open PowerShell or File Explorer.
3. Remove the application data directory:
   ```powershell
   Remove-Item -Recurse -Force "$env:LOCALAPPDATA\SentinelX"
   ```
4. All local event databases, evidence records, and logs are now permanently deleted.
