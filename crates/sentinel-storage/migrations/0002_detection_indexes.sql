-- Detection & Performance Indexes Migration

-- Events indexes: Query by timestamp, source address, destination port, and destination address
CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at);
CREATE INDEX IF NOT EXISTS idx_events_source_ip_observed_at ON events(source_ip, observed_at);
CREATE INDEX IF NOT EXISTS idx_events_dest_port_observed_at ON events(destination_port, observed_at);
CREATE INDEX IF NOT EXISTS idx_events_dest_ip_port ON events(destination_ip, destination_port);

-- Alerts indexes: Query by rule, status, fingerprint
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint);

-- Concurrency-safe unique index ensuring at most ONE active alert exists for a given fingerprint
-- Once an alert is resolved, it no longer conflicts with this index
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_active_fingerprint ON alerts(fingerprint) WHERE status IN ('open', 'acknowledged');

-- Alert evidence reverse lookup index (for retention integrity check and FK joins)
CREATE INDEX IF NOT EXISTS idx_alert_events_event_id ON alert_events(event_id);

-- Audit log indexes for timeline and entity audit history
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id);
