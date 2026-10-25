# Operational Runbook: SentinelX

## 1. Application Lifecycle & Startup

### 1.1 Startup Sequence
When launched (via desktop UI or CLI mode), SentinelX executes a deterministic initialization sequence:
1. **Directory Verification**: Verifies or creates the per-user configuration and database directory in `%LOCALAPPDATA%\SentinelX`.
2. **Database Configuration Validation**: Executes `DatabaseConfig::validate()`, verifying path presence, rejecting null bytes, and checking pool sizing.
3. **SQLite Schema Migrations**: Runs versioned embedded SQL migrations against `sentinelx.db`.
4. **Repository Initialization**: Initializes `EventRepository`, `AlertRepository`, `AuditRepository`, and `RetentionManager`.
5. **Coordinator Setup**: Instantiates `PipelineCoordinator` with the selected telemetry collector (`WindowsTcpCollector` in production, `MockCollector` in test/demo mode).
6. **Background Tasks**: Spawns telemetry polling loop on Tokio async runtime with bounded interval.
7. **Window Presentation**: Presents the Tauri 2 desktop window (`main`).

### 1.2 Graceful Shutdown Procedure
SentinelX handles shutdown cleanly to prevent database corruption, truncated write transactions, or dangling lock files:
- **Desktop Window Close**: Intercepted via `tauri::WindowEvent::CloseRequested` and `Destroyed`. Sets `shutdown_flag` atomic boolean, signals the background pipeline task to complete its current batch, flushes open transactions, and terminates the event loop.
- **CLI Mode (Ctrl+C)**: Handled via `tokio::signal::ctrl_c()`. Immediately halts new telemetry acquisition, executes a scheduled retention pass, and shuts down the connection pool cleanly.

---

## 2. Configuration Management

Configuration is stored in `%LOCALAPPDATA%\SentinelX\config.json`.

```json
{
  "polling_interval_ms": 1000,
  "database_path": "C:\\Users\\<User>\\AppData\\Local\\SentinelX\\sentinelx.db",
  "is_demo_mode": false,
  "theme": "dark",
  "log_verbosity": "info"
}
```

### Configuration Bounds & Validation Rules
- `polling_interval_ms`: Must reside between `100` and `3,600,000` ms (100 ms to 1 hour).
- `database_path`: Must be a valid filesystem path; cannot be empty or contain null bytes (`\0`).
- `theme`: Must be one of `dark`, `light`, or `system`.
- `log_verbosity`: Must be one of `trace`, `debug`, `info`, `warn`, or `error`.

---

## 3. Database Maintenance & Backups

### 3.1 SQLite WAL Mode Characteristics
SentinelX operates SQLite in Write-Ahead Logging (`WAL`) mode:
- Primary database file: `sentinelx.db`
- WAL journal file: `sentinelx.db-wal`
- Shared-memory index: `sentinelx.db-shm`

Do **not** delete `-wal` or `-shm` files while the application is running, as this will lead to database corruption.

### 3.2 Safe Backup Procedure
To perform a live, hot backup without stopping the application, use the SQLite Online Backup API or standard Windows CLI:
```powershell
sqlite3 "$env:LOCALAPPDATA\SentinelX\sentinelx.db" ".backup '$env:USERPROFILE\Desktop\sentinelx_backup.db'"
```
Alternatively, shut down SentinelX completely and copy `sentinelx.db` to a backup location.

### 3.3 Data Retention Management
Historical data retention is automatically managed by `RetentionManager`:
- **Default Policy**: 7-day retention (`retention_days = 7`), 30-day audit log retention (`audit_retention_days = 30`), batch size `500`.
- **Evidence Protection**: Strategy A retention strictly preserves all events associated with open or resolved security alerts via inner join with `alert_events`.

---

## 4. Diagnostics & Troubleshooting

| Symptom | Probable Cause | Remediation Step |
| :--- | :--- | :--- |
| **Telemetry status shows `NativeApiFailure`** | Security software blocking IP Helper API or insufficient permissions | Verify running as a standard desktop user; inspect Windows Defender / EDR logs for blocked calls to `GetExtendedTcpTable`. |
| **Database returns `database is locked (517)`** | Another process has opened `sentinelx.db` exclusively | Ensure only one instance of SentinelX is active; verify anti-virus software is not locking the SQLite file during active scanning. |
| **Frontend displays "Storage Error"** | Internal database or disk error occurred | Check application tracing logs for detailed error context; verify adequate free disk space on drive `C:`. |
| **Alerts not triggering for port scans** | Traffic is being sent to the same destination port repeatedly | Review rule NET-001 specification: distinct ports must meet or exceed threshold within the rolling window. |
| **High disk consumption** | High connection churn and extended retention period | Adjust retention policy in settings or manually trigger retention pass via CLI. |

---

## 5. Emergency Recovery

### Corrupt Database Recovery
If `sentinelx.db` becomes corrupt due to sudden power loss or external process termination:
1. Terminate all SentinelX processes:
   ```powershell
   Get-Process -Name "sentinel-app" -ErrorAction SilentlyContinue | Stop-Process -Force
   ```
2. Archive the corrupted database for offline forensic recovery:
   ```powershell
   Move-Item "$env:LOCALAPPDATA\SentinelX\sentinelx.db" "$env:LOCALAPPDATA\SentinelX\sentinelx_corrupted.db"
   ```
3. Restart SentinelX. The application will initialize a fresh, schema-migrated `sentinelx.db` automatically.
4. Attempt database salvage using SQLite CLI:
   ```powershell
   sqlite3 "$env:LOCALAPPDATA\SentinelX\sentinelx_corrupted.db" ".recover" | sqlite3 "$env:LOCALAPPDATA\SentinelX\salvaged.db"
   ```
