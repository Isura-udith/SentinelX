# SentinelX Comprehensive User & Operator Guide

This guide covers all features, operational views, detection workflows, and data management procedures for SentinelX on Windows 11.

---

## 1. Overview Dashboard

The **Overview Page** serves as the central command view:
- **Status Header:** Shows whether background telemetry collection is active, the active collector mode, database status, and last snapshot timestamp.
- **KPI Summary Cards:**
  - *Total Events Observed:* Count of normalized network connection events recorded.
  - *Active Alerts:* Unresolved security alerts currently requiring triage.
  - *High & Critical Threats:* Priority threat indicators.
  - *Endpoints Monitored:* Count of distinct external IP destinations observed.
- **Traffic Activity Chart:** Interactive time-series visualization displaying event volume and alert frequency over selectable intervals (1 Hour, 6 Hours, 24 Hours, 7 Days).
- **Alert Severity Breakdown:** Donut visualization categorizing alerts into Informational, Low, Medium, High, and Critical.

---

## 2. Inspecting Network Events

The **Network Events** page (`Activity` icon) provides a live, paginated table of observed host TCP activity:

- **Filter Controls:**
  - Search by IP address, port, PID, or protocol.
  - Filter by source type (`Live Windows TCP` vs. `Mock`).
  - Filter by TCP socket state (`ESTABLISHED`, `SYN_SENT`, `TIME_WAIT`, `CLOSE_WAIT`).
- **Event Inspection:**
  - Displays Timestamp (UTC), Source IP & Port, Destination IP & Port, Process ID (PID), Protocol, and Connection State.
  - Click any row to view expanded event metadata in JSON format.

---

## 3. Alert Triage & Incident Lifecycle

SentinelX enforces an auditable three-stage alert lifecycle:

```
[ New ] ──────> [ Acknowledged ] ──────> [ Resolved ]
```

### 3.1 Investigating an Alert
1. Navigate to **Security Alerts** in the left sidebar.
2. Filter by status (`New`, `Acknowledged`, `Resolved`) or severity (`Critical`, `High`, `Medium`, `Low`).
3. Click an alert row to navigate to **Alert Details**.

### 3.2 Reviewing Supporting Evidence
- The **Evidence Table** displays the exact connection events that triggered the detection rule.
- Even if global event retention runs, any event linked as alert evidence remains permanently preserved until the alert itself is purged.

### 3.3 Acknowledging an Alert
- Click **Acknowledge Alert**.
- Status updates immediately to `Acknowledged`.
- An entry is recorded in the immutable audit log with your user identity and timestamp.

### 3.4 Resolving an Alert
- Click **Resolve Alert**.
- Enter optional resolution notes (e.g., *"Authorized vulnerability scan from security team"* or *"False positive during load test"*).
- Status updates to `Resolved`.
- The alert disappears from active alert counts on the Overview dashboard.

---

## 4. Detection Rules Configuration

The **Detection Rules** page (`Sliders` icon) allows operators to inspect and tune detection algorithms:

### 4.1 Rule NET-001: Port-Scan-Like Activity Detection
- **Purpose:** Identifies horizontal or vertical port scanning attempts originating from a single IP.
- **Configurable Settings:**
  - *Rule Enable Toggle:* Activate or deactivate evaluation.
  - *Distinct Port Threshold:* Number of unique destination ports targeted before an alert triggers (default: 10 ports).
  - *Window Duration:* Rolling time window for counting distinct ports (default: 60 seconds).
  - *Alert Cooldown:* Suppression duration after an alert to prevent notification floods (default: 300 seconds).
  - *Max Evidence Events:* Cap on the number of event IDs attached to the alert (default: 20 events).

### 4.2 Rule NET-002: High Connection-Volume Anomaly Detection
- **Purpose:** Identifies sudden traffic bursts or DoS/brute-force patterns from a single source.
- **Configurable Settings:**
  - *Connection Burst Threshold:* Number of connections initiated within window (default: 20 connections).
  - *Window Duration:* Observation window (default: 60 seconds).
  - *Cooldown Window:* Suppression interval (default: 300 seconds).

Click **Update Rule Configuration** to persist changes immediately to the `rule_config` database table.

---

## 5. Telemetry & Collector Controls

The **Telemetry** page (`Radio` icon) provides direct control over data ingestion:

- **Start / Stop Telemetry:** Pause background polling during maintenance without closing the application.
- **Polling Interval:** Adjust snapshot frequency (default: 1,000 ms).
- **Collector Mode:** Toggle between Live Windows TCP collection and Demonstration Mock mode.
- **Performance Diagnostics:**
  - Raw records observed vs. normalized events produced.
  - Skipped records (listening sockets, localhost-to-localhost connections).
  - Average collection duration in milliseconds.
  - Last successful collection timestamp and error counts.

---

## 6. Audit History Log

The **Audit History** page (`History` icon) provides a tamper-evident chronological timeline:
- Records all actions taken by operators or automated subsystems:
  - `ALERT_DETECTED`
  - `ALERT_ACKNOWLEDGED`
  - `ALERT_RESOLVED`
  - `RULE_UPDATED`
  - `SETTINGS_UPDATED`
- Displays Actor, Action, Target Entity, Timestamp, and structured change diffs in JSON.

---

## 7. Application Settings

The **Settings** page allows operators to configure:
- **Database Path:** Displays the current SQLite database location (`%LOCALAPPDATA%\SentinelX\sentinelx.db`).
- **Event Retention Window:** Configures how many days telemetry events are kept (default: 30 days).
- **Audit Retention Window:** Configures how many days audit logs are kept (default: 90 days).
- **UI Refresh Frequency:** Dashboard auto-refresh interval (5s, 10s, 30s, 60s).
- **About SentinelX:** Discloses version, target platform, license, repository, and defensive scope boundaries.
