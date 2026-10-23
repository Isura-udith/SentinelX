-- Initial Schema Migration: Events, Alerts, Alert-Event Relationships, Detection Rules, and Audit Log

-- 1. Events Table: Persisted network telemetry observations
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY NOT NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    protocol TEXT NOT NULL,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    process_id INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    ingested_at TEXT NOT NULL
);

-- 2. Alerts Table: Security detection alerts
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved')),
    event_count INTEGER NOT NULL,
    fingerprint TEXT NOT NULL
);

-- 3. Alert-Events Relationship Table: Durable link between alert and evidence
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);

-- 4. Detection Rules Metadata Table
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    rule_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 5. Audit Log Table: Security-relevant operator actions and system operations
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}'
);
