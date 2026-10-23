# Data Retention & Evidence Preservation Policy: SentinelX

## 1. Overview & Objectives

SentinelX operates in local workstation and endpoint environments where disk space, write-lock contention, and forensic evidentiary integrity must be carefully balanced.

The data retention subsystem (`sentinel-storage::retention`) enforces automated, foreign-key-safe data aging while preserving the forensic chain of custody for all security alerts.

---

## 2. Retention Periods & Configuration

| Data Category | Default Retention Period | CLI Configuration | Description |
| :--- | :--- | :--- | :--- |
| **Telemetry Events** (`events`) | **30 Days** | `--retention-days <DAYS>` | Raw normalized connection observations from Windows TCP snapshots. |
| **Security Alerts** (`alerts`) | **Indefinite (Active) / Manual** | N/A | Active (`open`, `acknowledged`) alerts are **never** automatically deleted. |
| **Alert Evidence Links** (`alert_events`) | **Indefinite** (tied to alert) | N/A | Association mapping linking alerts to supporting event records. |
| **Audit Log Records** (`audit_log`) | **90 Days** | Configurable via `RetentionPolicy` | Security triage records (status transitions, rule reconfigurations, retention runs). |
| **Detection Rule Metadata** (`detection_rules`) | **Permanent** | N/A | Seed catalog of registered analytical rules. |

To disable automated retention cleanup during execution (e.g., in long-running forensic captures), pass the `--no-retention` flag at launch.

---

## 3. Forensic Evidence Preservation Strategy

When purging expired events, SentinelX employs **Strategy A: Active Evidence Preservation**:

```sql
DELETE FROM events
WHERE id IN (
    SELECT id FROM events
    WHERE observed_at < ?
      AND id NOT IN (SELECT event_id FROM alert_events)
    LIMIT ?
);
```

### Invariants:
1. **Zero Dangling Foreign Keys**:
   - The `alert_events` table enforces `FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE RESTRICT`.
   - SQLite foreign-key enforcement is enabled on every connection (`PRAGMA foreign_keys = ON;`). Attempting to delete an event referenced by an alert results in a foreign-key constraint violation.
2. **Forensic Integrity**:
   - Raw connection records that contributed to a `SecurityAlert` remain queryable and verifiable indefinitely, even after their normal 30-day lifecycle expires.
   - Security analysts conducting retrospective incident response can inspect the exact telemetry rows that triggered the detection.
3. **No Redaction Ambiguity**:
   - The system never presents an alert with "missing" or "expired" evidence IDs without explicit operator intention.

---

## 4. Batched Deletion & Concurrency Architecture

SQLite uses database-level locking for write operations. To prevent long-running write transactions that could stall incoming telemetry ingestion:

1. **Chunked Batches**:
   - Expired records are deleted in configurable chunks (default: 500 rows per batch).
2. **Short Transaction Windows**:
   - Each chunk executes within its own discrete transaction, committing immediately and releasing the write lock.
3. **Loop Until Drained**:
   - The deletion cycle repeats iteratively until fewer than the batch limit rows are deleted, indicating that all expired non-evidence records have been purged.
4. **Structured Logging & Metrics**:
   - The cleanup cycle reports total rows deleted, batches executed, and duration via structured `tracing` events and updates `PipelineMetrics::retention_purges`.

---

## 5. Audit Log Retention

The `audit_log` table records security-relevant analyst actions, including:
- Alert acknowledgement (`status_transition: open -> acknowledged`).
- Alert resolution (`status_transition: acknowledged -> resolved`).
- Data retention execution records.
- Rule configuration changes.

Audit records are retained for a minimum of **90 days**. Deletion is similarly batched and logged.

---

## 6. Backup & Disaster Recovery Considerations

Because SentinelX uses SQLite in Write-Ahead Logging (WAL) mode:

1. **Hot Backups**:
   - Copying the `.db` file alone while the database is actively being written to can result in an inconsistent snapshot if uncheckpointed WAL frames exist in `.db-wal`.
   - Use SQLite's online backup API or ensure the database is closed or checkpointed (`PRAGMA wal_checkpoint(TRUNCATE);`) prior to file-system backups.
2. **File Locations**:
   - Default database location: `%LOCALAPPDATA%\SentinelX\sentinelx.db` (or `./target/sentinelx.db` during development).
   - In production deployments, restrict the parent directory permissions to `Administrators` and `SYSTEM` using Windows NTFS Access Control Lists (ACLs).
3. **Zero Data Loss on Migration**:
   - Database migrations use embedded, versioned SQL scripts. Migrations execute inside transactions, rolling back completely if a step fails.
   - The application **never** deletes or recreates an existing database file upon migration error.
