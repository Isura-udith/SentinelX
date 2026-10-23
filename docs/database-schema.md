# Database Schema Specification: SentinelX

## 1. Storage Architecture Overview

SentinelX uses an embedded SQLite database as its local persistence layer.
The database engine is managed via `sentinel-storage` and leverages SQLx for compile-time verified schema migrations, connection pooling, and transactional operations.

### Key Operational Design Principles

- **Strict Repository Boundaries**: Detection rules and telemetry collectors never execute SQL queries directly. All storage interactions are mediated through typed repository interfaces ([`EventRepository`](../crates/sentinel-storage/src/events.rs), [`AlertRepository`](../crates/sentinel-storage/src/alerts.rs), [`AuditLogRepository`](../crates/sentinel-storage/src/audit.rs), and [`RetentionManager`](../crates/sentinel-storage/src/retention.rs)).
- **Foreign Key Integrity**: SQLite foreign key constraints (`PRAGMA foreign_keys = ON;`) are enforced on every database connection.
- **Write-Ahead Logging (WAL)**: SQLite is initialized with `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = NORMAL;`, allowing concurrent readers without blocking writers.
- **Busy Timeout**: Connections are configured with a 5,000ms busy timeout (`PRAGMA busy_timeout = 5000;`) to handle lock contention gracefully.
- **Forensic Evidence Preservation**: Network events linked to security alerts are protected against automated data retention purges via subquery filtering and foreign key constraints.

---

## 2. Database Tables and Relationships

### Entity-Relationship Diagram

```
┌────────────────────────┐                   ┌────────────────────────┐
│         events         │                   │         alerts         │
├────────────────────────┤                   ├────────────────────────┤
│ id (PK, TEXT/UUID)     │◄──┐           ┌──►│ id (PK, TEXT/UUID)     │
│ observed_at (TEXT)     │   │           │   │ rule_id (TEXT)         │
│ source (TEXT)          │   │           │   │ rule_version (TEXT)    │
│ protocol (TEXT)        │   │           │   │ severity (TEXT)        │
│ source_ip (TEXT, NULL) │   │           │   │ title (TEXT)           │
│ source_port (INT, NULL)│   │           │   │ description (TEXT)     │
│ destination_ip (TEXT)  │   │           │   │ first_seen (TEXT)      │
│ destination_port (INT) │   │           │   │ last_seen (TEXT)       │
│ process_id (INT, NULL) │   │           │   │ created_at (TEXT)      │
│ metadata_json (TEXT)   │   │           │   │ updated_at (TEXT)      │
│ ingested_at (TEXT)     │   │           │   │ status (TEXT)          │
└────────────────────────┘   │           │   │ event_count (INT)      │
                             │           │   │ fingerprint (TEXT)     │
                             │           │   └────────────────────────┘
                      ┌──────┴───────────┴──────┐
                      │      alert_events       │
                      ├─────────────────────────┤
                      │ alert_id (PK, FK)       │
                      │ event_id (PK, FK)       │
                      │ linked_at (TEXT)        │
                      └─────────────────────────┘

┌────────────────────────┐                   ┌────────────────────────┐
│    detection_rules     │                   │       audit_log        │
├────────────────────────┤                   ├────────────────────────┤
│ rule_id (PK, TEXT)     │                   │ id (PK, TEXT/UUID)     │
│ name (TEXT)            │                   │ timestamp (TEXT)       │
│ description (TEXT)     │                   │ actor (TEXT)           │
│ enabled (INT)          │                   │ action (TEXT)          │
│ rule_version (TEXT)    │                   │ target_type (TEXT)     │
│ created_at (TEXT)      │                   │ target_id (TEXT, NULL) │
│ updated_at (TEXT)      │                   │ details_json (TEXT)    │
└────────────────────────┘                   └────────────────────────┘
```

---

## 3. Table Definitions

### 3.1 `events` Table
Persists normalized telemetry connection snapshots captured by telemetry collectors.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY NOT NULL` | UUID v4 string representing event identity. Stable for idempotent retries. |
| `observed_at` | `TEXT` | `NOT NULL` | UTC ISO-8601 observation timestamp when snapshot was captured. |
| `source` | `TEXT` | `NOT NULL` | Collector origin (`windows_tcp_snapshot`, `synthetic_simulator`, etc.). |
| `protocol` | `TEXT` | `NOT NULL` | Transport protocol (`TCP`, `UDP`). |
| `source_ip` | `TEXT` | `NULLABLE` | Local source IPv4 or IPv6 address. |
| `source_port` | `INTEGER` | `NULLABLE` | Local source port (1..=65535). |
| `destination_ip` | `TEXT` | `NULLABLE` | Remote destination IPv4 or IPv6 address. |
| `destination_port`| `INTEGER` | `NULLABLE` | Remote destination port (1..=65535). |
| `process_id` | `INTEGER` | `NULLABLE` | Operating system process ID owning the socket. |
| `metadata_json` | `TEXT` | `NOT NULL DEFAULT '{}'` | Validated structured key-value metadata container. |
| `ingested_at` | `TEXT` | `NOT NULL` | UTC ISO-8601 timestamp when the record was persisted to SQLite. |

### 3.2 `alerts` Table
Stores analytical security detection alerts generated by detection rules.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY NOT NULL` | Unique UUID v4 alert identifier. |
| `rule_id` | `TEXT` | `NOT NULL` | Stable detection rule identifier (e.g. `NET-001`, `NET-002`). |
| `rule_version` | `TEXT` | `NOT NULL` | Version string of the rule configuration or logic. |
| `severity` | `TEXT` | `NOT NULL` | Triage severity (`informational`, `low`, `medium`, `high`, `critical`). |
| `title` | `TEXT` | `NOT NULL` | Concise summary of the alert condition. |
| `description` | `TEXT` | `NOT NULL` | Contextual explanation and false-positive triage guidance. |
| `first_seen` | `TEXT` | `NOT NULL` | UTC timestamp of earliest supporting observation in window. |
| `last_seen` | `TEXT` | `NOT NULL` | UTC timestamp of most recent supporting observation. |
| `created_at` | `TEXT` | `NOT NULL` | UTC timestamp when alert was first committed. |
| `updated_at` | `TEXT` | `NOT NULL` | UTC timestamp of most recent alert modification or correlation. |
| `status` | `TEXT` | `NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved'))` | Operational lifecycle triage state. |
| `event_count` | `INTEGER` | `NOT NULL` | Cumulative count of supporting observations. |
| `fingerprint` | `TEXT` | `NOT NULL` | Stable grouping key for alert deduplication and correlation. |

### 3.3 `alert_events` Table
Maintains durable, many-to-many associations between alerts and supporting forensic evidence events.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `alert_id` | `TEXT` | `NOT NULL REFERENCES alerts(id) ON DELETE CASCADE` | Foreign key referencing the parent alert. |
| `event_id` | `TEXT` | `NOT NULL REFERENCES events(id) ON DELETE RESTRICT` | Foreign key referencing supporting network event. |
| `linked_at` | `TEXT` | `NOT NULL` | UTC timestamp when the event was linked to the alert. |

*Primary Key*: Composite `(alert_id, event_id)`. Prevents duplicate links.

### 3.4 `detection_rules` Table
Stores metadata and version tracking for registered detection rules.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `rule_id` | `TEXT` | `PRIMARY KEY NOT NULL` | Rule identifier (`NET-001`, `NET-002`). |
| `name` | `TEXT` | `NOT NULL` | Human-readable rule name. |
| `description` | `TEXT` | `NOT NULL` | Technical description of rule logic. |
| `enabled` | `INTEGER` | `NOT NULL DEFAULT 1` | 1 if active, 0 if disabled. |
| `rule_version` | `TEXT` | `NOT NULL` | Version string. |
| `created_at` | `TEXT` | `NOT NULL` | UTC registration timestamp. |
| `updated_at` | `TEXT` | `NOT NULL` | UTC configuration update timestamp. |

### 3.5 `audit_log` Table
Maintains a tamper-evident record of administrative and operator security actions.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY NOT NULL` | UUID v4 audit record identifier. |
| `timestamp` | `TEXT` | `NOT NULL` | UTC timestamp of the action. |
| `actor` | `TEXT` | `NOT NULL` | Actor identifier (e.g. `operator`, `analyst`, `sentinel_daemon`). |
| `action` | `TEXT` | `NOT NULL` | Action classification (`alert_created`, `alert_acknowledged`, `alert_resolved`, `retention_cleanup`). |
| `target_type` | `TEXT` | `NOT NULL` | Target entity classification (`alert`, `rule`, `retention`, `system`). |
| `target_id` | `TEXT` | `NULLABLE` | Identifier of modified entity. |
| `details_json` | `TEXT` | `NOT NULL DEFAULT '{}'` | Structured JSON context and notes. |

---

## 4. Database Indexes

Every index is designed for a verified query access pattern:

| Index Name | Table | Columns | Purpose |
| :--- | :--- | :--- | :--- |
| `idx_events_observed_at` | `events` | `(observed_at)` | Bounded time-range queries and retention cutoff lookups. |
| `idx_events_source_ip_observed_at` | `events` | `(source_ip, observed_at)` | Source IP historical queries and timeline reconstruction. |
| `idx_events_dest_port_observed_at` | `events` | `(destination_port, observed_at)` | Service-level port reconnaissance queries. |
| `idx_events_dest_ip_port` | `events` | `(destination_ip, destination_port)` | Destination endpoint connection auditing. |
| `idx_alerts_rule_id` | `alerts` | `(rule_id, created_at)` | Filtering alerts by rule specification. |
| `idx_alerts_status` | `alerts` | `(status, created_at)` | Analyst queue triage lookups (e.g., all `open` alerts). |
| `idx_alerts_fingerprint` | `alerts` | `(fingerprint)` | Fast active alert lookup during correlation. |
| `idx_alerts_active_fingerprint` | `alerts` | `(fingerprint) WHERE status IN ('open', 'acknowledged')` | **Partial Unique Index**: Enforces that at most ONE active alert exists per fingerprint. |
| `idx_alert_events_event_id` | `alert_events`| `(event_id)` | Reverse lookup checking whether an event is protected by an active alert during retention cleanup. |
| `idx_audit_log_timestamp` | `audit_log` | `(timestamp)` | Chronological audit log timeline queries and audit retention purging. |
| `idx_audit_log_target` | `audit_log` | `(target_type, target_id)` | Audit history queries for a specific security alert or rule. |

---

## 5. Schema Versioning & Embedded Migrations

Migrations are embedded into the compiled binary via SQLx `migrate!("./migrations")`:

1. `0001_initial_schema.sql`: Creates core tables (`events`, `alerts`, `alert_events`, `detection_rules`, `audit_log`).
2. `0002_detection_indexes.sql`: Creates specialized analytical and partial unique indexes.

Migrations are applied automatically during [`Database::new()`](../crates/sentinel-storage/src/database.rs) initialization. If a migration fails, the error is immediately returned as [`StorageError::Migration`](../crates/sentinel-storage/src/error.rs) and the application terminates without attempting destructive recovery.
