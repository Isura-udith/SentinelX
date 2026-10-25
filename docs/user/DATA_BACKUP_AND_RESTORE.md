# SentinelX Data Backup & Recovery Guide

This guide provides the official, safe procedure for backing up and restoring SentinelX event history, security alerts, audit logs, and configuration on Windows 11.

---

## 1. Important Prerequisites

> **CRITICAL RULE:** Always close the SentinelX application completely before performing backup or restore operations. Copying a live SQLite database while active WAL (Write-Ahead Logging) write transactions are in-flight can lead to inconsistent backup states.

Ensure `sentinel-app.exe` is not running in Windows Task Manager before proceeding.

---

## 2. Safe Manual Backup Procedure

SentinelX stores all state inside `%LOCALAPPDATA%\SentinelX\`.

### Step 1: Open PowerShell
Press `Win + X` and select **Terminal** or **PowerShell**.

### Step 2: Define Backup Destination
Create a backup directory (e.g., in your Documents folder):

```powershell
$backupDir = "$env:USERPROFILE\Documents\SentinelX_Backups\Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
```

### Step 3: Copy Database & Configuration Files
Copy the primary database file, WAL files, and settings:

```powershell
$sourceDir = "$env:LOCALAPPDATA\SentinelX"

# Copy primary database and journals
Copy-Item "$sourceDir\sentinelx.db*" -Destination $backupDir -Force

# Copy user configuration
Copy-Item "$sourceDir\settings.json" -Destination $backupDir -Force -ErrorAction SilentlyContinue

Write-Host "SentinelX backup completed successfully to: $backupDir" -ForegroundColor Green
```

### Files Captured in Backup:
- `sentinelx.db`: Primary SQLite database containing events, alerts, rule configs, and audit logs.
- `sentinelx.db-wal`: Write-Ahead Log journal containing recent uncheckpointed transactions.
- `sentinelx.db-shm`: Shared-memory index for WAL mode.
- `settings.json`: User dashboard preferences and retention configuration.

---

## 3. Safe Recovery / Restore Procedure

To restore SentinelX data from a prior backup (for example, when moving to a new Windows 11 workstation or recovering from an issue):

### Step 1: Exit SentinelX
Ensure SentinelX is not running.

### Step 2: Locate Backup Directory
Identify your target backup folder containing `sentinelx.db`.

### Step 3: Restore Files via PowerShell
```powershell
$backupDir = "$env:USERPROFILE\Documents\SentinelX_Backups\<Your_Backup_Folder>"
$targetDir = "$env:LOCALAPPDATA\SentinelX"

# Ensure target directory exists
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

# Remove stale WAL/SHM locks in target if present
Remove-Item "$targetDir\sentinelx.db-wal" -Force -ErrorAction SilentlyContinue
Remove-Item "$targetDir\sentinelx.db-shm" -Force -ErrorAction SilentlyContinue

# Copy backup database and settings
Copy-Item "$backupDir\sentinelx.db" -Destination $targetDir -Force
Copy-Item "$backupDir\settings.json" -Destination $targetDir -Force -ErrorAction SilentlyContinue

Write-Host "SentinelX data restored successfully." -ForegroundColor Green
```

### Step 4: Launch SentinelX
Start SentinelX from the Start Menu. The application will automatically connect to the restored database, verify schema integrity, apply any new version migrations automatically, and load your historical events and alerts.
