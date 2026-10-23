# Domain Model Specification: SentinelX

## 1. Domain Philosophy: Instantaneous Connection Observations

A fundamental concept in SentinelX is that a [`NetworkEvent`](../crates/sentinel-core/src/event.rs) represents an **instantaneous connection observation** — a point-in-time snapshot of an active network socket or packet metadata sample.

### Critical Operational Boundary
> **Important**:
> A snapshot observation is **not** a continuous packet capture or complete lifecycle record.
> Connections that initiate and terminate between polling intervals may not be captured in periodic snapshots.
> Detection rules in SentinelX are deliberately engineered to analyze discrete observation batches without assuming unbroken session visibility.

---

## 2. Core Identifiers

SentinelX uses strongly typed transparent newtypes to prevent identifier confusion (e.g., passing an event ID where an alert ID is expected):

| Type | Underlying Representation | Serialization | Purpose |
| :--- | :--- | :--- | :--- |
| **`EventId`** | `uuid::Uuid` | UUID v4 string | Unique identifier for each network observation. |
| **`AlertId`** | `uuid::Uuid` | UUID v4 string | Unique identifier for each security alert instance. |
| **`RuleId`** | `String` | Raw string (e.g., `"NET-001"`) | Identifier for a detection rule. Rejects empty/whitespace strings. |
| **`ProcessId`** | `u32` | Numeric integer | Host operating system process identifier (0..=4,194,304). |

---

## 3. Enumerations

### 3.1 `NetworkProtocol`
Specifies transport layer protocols observed in connection telemetry.
- `Tcp`: Transmission Control Protocol (`"TCP"` in JSON).
- `Udp`: User Datagram Protocol (`"UDP"` in JSON).

### 3.2 `TelemetrySource`
Documents the source provenance of an observation.
- `SyntheticSimulator`: Generated test data for local verification (`"synthetic_simulator"`).
- `WindowsTcpSnapshot`: Periodic socket table query via Windows IP Helper (`"windows_tcp_snapshot"`).
- `WindowsEventTelemetry`: Kernel or ETW connection telemetry (`"windows_event_telemetry"`).
- `PacketMetadata`: Lightweight packet inspection without payload capture (`"packet_metadata"`).

### 3.3 `AlertSeverity`
Conveys triage urgency based on defensive criteria:
- `Informational`: Baseline metrics or contextual events.
- `Low`: Minor variance unlikely to indicate malicious intent.
- `Medium`: Suspicious threshold breach exceeding typical baseline (e.g., initial port reconnaissance).
- `High`: Extensive scanning or high-confidence malicious pattern requiring expedited review.
- `Critical`: High-velocity reconnaissance or severe multi-service compromise attempt.

### 3.4 `AlertStatus`
Operational triage lifecycle of an alert:
- `Open`: Newly emitted alert awaiting triage.
- `Acknowledged`: Acknowledged by a security analyst and under active review.
- `Resolved`: Investigated and closed (benign false positive or mitigated).

---

## 4. `NetworkEvent` Schema

| Field | Type | Required / Optional | Constraints & Validation |
| :--- | :--- | :--- | :--- |
| `id` | `EventId` | Required | UUID v4. |
| `timestamp` | `DateTime<Utc>` | Required | Valid UTC observation timestamp. |
| `source` | `TelemetrySource` | Required | Documented telemetry provenance. |
| `protocol` | `NetworkProtocol` | Required | TCP or UDP. |
| `source_ip` | `Option<IpAddr>` | Optional | Standard IPv4 or IPv6 address. |
| `source_port` | `Option<u16>` | Optional | Valid range 1..=65535. Port 0 is rejected as invalid. |
| `destination_ip` | `Option<IpAddr>` | Optional | Standard IPv4 or IPv6 address. |
| `destination_port` | `Option<u16>` | Optional | Valid range 1..=65535. Port 0 is rejected as invalid. |
| `process_id` | `Option<ProcessId>` | Optional | Operating system PID (0..=4,194,304). |
| `metadata` | `EventMetadata` | Required (default empty) | Max 16 entries; keys <= 64 bytes; values <= 256 bytes. |

---

## 5. `SecurityAlert` Schema

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `AlertId` | Unique alert instance identifier. |
| `rule_id` | `RuleId` | Identifying rule (e.g., `NET-001`). |
| `severity` | `AlertSeverity` | Analytical severity tier. |
| `title` | `String` | Concise human-readable summary of the condition. |
| `explanation` | `String` | Detailed explanation of evidence, thresholds, and caveats. |
| `first_observed_at` | `DateTime<Utc>` | Earliest timestamp among supporting events. |
| `last_observed_at` | `DateTime<Utc>` | Latest timestamp among supporting events (`>= first_observed_at`). |
| `observation_count` | `usize` | Total supporting observations evaluated. |
| `source_ip` | `Option<IpAddr>` | Source address associated with the alert. |
| `evidence_event_ids` | `Vec<EventId>` | Bounded list of representative event IDs serving as forensic evidence. |
| `status` | `AlertStatus` | Operational triage state. |

---

## 6. `DetectionConfig` Schema

| Parameter | Type | Default | Validation Criteria |
| :--- | :--- | :--- | :--- |
| `distinct_port_threshold` | `u16` | 10 | Must be > 0. `threshold * 4` must not overflow `u16`. |
| `window_duration` | `chrono::Duration` | 60 seconds | Must be strictly positive (> 0s). |
| `alert_cooldown` | `Option<Duration>` | 300 seconds | Optional cooldown window. |
| `max_batch_size` | `usize` | 10,000 | Must be > 0. Bounds batch ingestion memory. |
| `max_evidence_ids_per_alert` | `usize` | 50 | Must be > 0. Caps alert payload memory. |
