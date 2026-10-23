# Architecture Overview: SentinelX

## 1. Architectural Mission

SentinelX delivers a modular, robust, and explainable defensive cybersecurity monitoring framework written in Rust.

The system decouples data acquisition, normalized domain representations, analytical detection logic, persistent storage, asynchronous scheduling, and operational telemetry into distinct architectural boundaries.

---

## 2. Workspace Crate Separation

SentinelX is structured as a virtual Cargo workspace containing five decoupled crates:

```
crates/
├── sentinel-core/          # Pure domain models, validation, errors, config
├── sentinel-collector/     # Telemetry collectors (Windows TCP snapshots & deterministic mock)
├── sentinel-detection/     # Pluggable detection rules, stateful rolling windows, and analytical engine
├── sentinel-storage/       # SQLite persistence, migrations, and typed repositories
└── sentinel-app/           # Asynchronous orchestration, CLI execution, pipeline coordination, and reporting
```

### Dependency Graph

```
                                 [ sentinel-app ]
                                   │    │    │
          ┌────────────────────────┘    │    └────────────────────────┐
          ▼                             ▼                             ▼
 [ sentinel-collector ]       [ sentinel-detection ]       [ sentinel-storage ]
          │                             │                             │
          └─────────────────────────────┼─────────────────────────────┘
                                        ▼
                                [ sentinel-core ]
```

### Crate Responsibilities

#### `sentinel-core`
- **Role**: Pure domain kernel (`#![forbid(unsafe_code)]`).
- **Dependencies**: Minimal external crates (`serde`, `serde_json`, `chrono`, `uuid`, `thiserror`). No I/O, no network bindings, no Windows APIs, no database drivers.
- **Components**:
  - `event`: [`NetworkEvent`](../crates/sentinel-core/src/event.rs), [`EventId`](../crates/sentinel-core/src/event.rs), [`NetworkProtocol`](../crates/sentinel-core/src/event.rs), [`TelemetrySource`](../crates/sentinel-core/src/event.rs), [`ProcessId`](../crates/sentinel-core/src/event.rs), bounded [`EventMetadata`](../crates/sentinel-core/src/event.rs).
  - `alert`: [`SecurityAlert`](../crates/sentinel-core/src/alert.rs), [`AlertId`](../crates/sentinel-core/src/alert.rs), [`RuleId`](../crates/sentinel-core/src/alert.rs), [`AlertSeverity`](../crates/sentinel-core/src/alert.rs), [`AlertStatus`](../crates/sentinel-core/src/alert.rs).
  - `config`: [`DetectionConfig`](../crates/sentinel-core/src/config.rs) and threshold validation.
  - `error`: Strongly typed [`DomainError`](../crates/sentinel-core/src/error.rs) and [`ConfigError`](../crates/sentinel-core/src/error.rs).

#### `sentinel-collector`
- **Role**: Telemetry ingestion and normalization subsystem.
- **Dependencies**: Depends on `sentinel-core`, `chrono`, `tracing`, `thiserror`, and target-conditional `windows-sys` (`target_os = "windows"`).
- **Components**:
  - `source`: [`TelemetryCollector`](../crates/sentinel-collector/src/source.rs) trait, [`CollectionBatch`](../crates/sentinel-collector/src/source.rs), [`CollectionMetadata`](../crates/sentinel-collector/src/source.rs).
  - `windows_tcp`: [`WindowsTcpCollector`](../crates/sentinel-collector/src/windows_tcp.rs) interfacing with native Windows IP Helper API (`GetExtendedTcpTable`) for IPv4 and IPv6 tables. Unsafe FFI operations are strictly isolated with alignment-safe reads.
  - `mock`: [`MockCollector`](../crates/sentinel-collector/src/mock.rs) providing deterministic, reproducible fixtures (`PortSweep`, `RepeatedPort`, `NormalTraffic`, `Mixed`, `Empty`, and simulated failure injection) for tests and cross-platform development.
  - `normalize`: [`RawTcpRecord`](../crates/sentinel-collector/src/normalize.rs), [`TcpState`](../crates/sentinel-collector/src/normalize.rs), [`normalize_tcp_record`](../crates/sentinel-collector/src/normalize.rs), byte-order decoding, and explicit listening socket skip filtering.
  - `stats`: [`CollectionStats`](../crates/sentinel-collector/src/stats.rs) tracking cycles, records observed, events normalized, records skipped, and collection latency.
  - `error`: Strongly typed [`CollectorError`](../crates/sentinel-collector/src/error.rs).

#### `sentinel-detection`
- **Role**: Analytical detection engine (`#![forbid(unsafe_code)]`).
- **Dependencies**: Depends strictly on `sentinel-core`, `chrono`, and diagnostic `tracing`. No database drivers.
- **Components**:
  - `engine`: [`DetectionEngine`](../crates/sentinel-detection/src/engine.rs) orchestrating batch evaluation, bounding batch sizes, and guaranteeing deterministic sorting.
  - `rules`: Pluggable [`DetectionRule`](../crates/sentinel-detection/src/engine.rs) trait.
  - `port_scan`: [`PortScanRule`](../crates/sentinel-detection/src/rules/port_scan.rs) (`NET-001`): Stateful event-time rolling window, distinct destination port counting, duplicate `EventId` suppression, memory bounds, and cooldown logic.
  - `connection_burst`: [`ConnectionBurstRule`](../crates/sentinel-detection/src/rules/connection_burst.rs) (`NET-002`): Stateful connection volume anomaly heuristic tracking observation volume within a sliding window.

#### `sentinel-storage`
- **Role**: SQLite persistence layer, migrations, and typed repositories (`#![forbid(unsafe_code)]`).
- **Dependencies**: Depends on `sentinel-core`, `sqlx` (SQLite, runtime-tokio, chrono, uuid, migrate), `chrono`, `uuid`, `thiserror`, and `tracing`.
- **Components**:
  - `database`: [`Database`](../crates/sentinel-storage/src/database.rs) connection pool, WAL mode, foreign key enforcement, 5s busy timeout, and embedded migration runner.
  - `events`: [`EventRepository`](../crates/sentinel-storage/src/events.rs) providing transactional batch insertion, idempotent `EventId` handling, bounded pagination, and time-range filtering.
  - `alerts`: [`AlertRepository`](../crates/sentinel-storage/src/alerts.rs) providing alert creation, alert querying, `upsert_correlated_alert`, evidence linking (`alert_events`), and audited status transitions.
  - `audit`: [`AuditLogRepository`](../crates/sentinel-storage/src/audit.rs) logging security-relevant triage events.
  - `retention`: [`RetentionManager`](../crates/sentinel-storage/src/retention.rs) executing batched deletion while preserving events referenced in active or historical alerts.
  - `error`: Strongly typed [`StorageError`](../crates/sentinel-storage/src/error.rs).

#### `sentinel-app`
- **Role**: Application orchestration, pipeline coordination, and command-line execution.
- **Dependencies**: Orchestrates `sentinel-core`, `sentinel-collector`, `sentinel-detection`, `sentinel-storage`, Tokio runtime, `tracing-subscriber`, and `anyhow`.
- **Components**:
  - `pipeline`: [`PipelineCoordinator`](../crates/sentinel-app/src/pipeline.rs) managing the end-to-end ingestion and detection lifecycle with structured metrics (`PipelineMetrics`).
  - `telemetry`: [`TelemetryScheduler`](../crates/sentinel-app/src/telemetry.rs) running asynchronous polling loops, isolating blocking FFI collection via `tokio::task::spawn_blocking`, and handling graceful shutdown on `Ctrl+C`.
  - `main`: CLI entry point supporting `--mock`, `--interval-ms`, `--max-cycles`, `--continuous`, `--db`, `--retention-days`, and `--no-retention`.

---

## 3. End-to-End Processing Pipeline

```
  [ Windows OS Kernel / TCP Stack ]
                │
                │ GetExtendedTcpTable (IP Helper API)
                ▼
  [ WindowsTcpCollector ]
  - Two-pass dynamic buffer sizing
  - read_unaligned raw memory copy
  - Big-endian address/port decoding
                │
                │ Vec<RawTcpRecord>
                ▼
  [ Normalization Subsystem ]
  - Filter listening sockets (remote port 0 / LISTEN state)
  - Map native dwState to TcpState enum
  - Attach ProcessId & Utc timestamp
                │
                │ CollectionBatch (Vec<NetworkEvent>)
                ▼
  [ PipelineCoordinator ]
  - Record cycle latency and counters
                │
                │ Transactional Batch Insert
                ▼
  [ EventRepository (SQLite) ]
  - Batch insert with INSERT OR IGNORE by EventId
  - High-performance WAL mode
                │
                │ Normalized Event Stream
                ▼
  [ DetectionEngine ]
  - Stateful event-time rolling window
  - Suppress duplicate EventIds
  - Evaluate NET-001 (distinct ports >= threshold)
  - Evaluate NET-002 (observation volume >= threshold)
                │
                │ Vec<SecurityAlert>
                ▼
  [ Alert Correlation & Persistence (AlertRepository) ]
  - Check active fingerprint (NET-001:{source_ip}, NET-002:{source_ip})
  - Existing active alert -> advance last_seen, increment count, link new events
  - New fingerprint -> create alert & insert alert_events links
                │
                │ Automated Retention Cycle (Optional)
                ▼
  [ RetentionManager ]
  - Delete expired events NOT linked to alerts (Strategy A)
  - Delete expired audit logs
                │
                ▼
  [ Structured Reporting / Analyst Triage ]
  - Formatted alert output with explainability context
  - Execution summary statistics table
```

---

## 4. State Management and Restart Behavior

### In-Memory vs. Persistent State
| State Component | Location | Lifespan | Recovery on Restart |
| :--- | :--- | :--- | :--- |
| **Raw Telemetry Events** | SQLite (`events`) | Configurable (30 days default) | Fully persistent |
| **Security Alerts** | SQLite (`alerts`) | Indefinite / Manual triage | Fully persistent |
| **Evidence Links** | SQLite (`alert_events`)| Indefinite (tied to alert) | Fully persistent |
| **Audit Log** | SQLite (`audit_log`)| 90 days | Fully persistent |
| **Rule Configuration**| In-memory / Code defaults | Process lifetime | Initialized at launch |
| **Rolling Window State**| In-memory (`PortScanRule`, `ConnectionBurstRule`) | Process lifetime | Cleanly reinitialized (empty) |

### Restart Semantics:
- The detection engine initializes with a fresh in-memory state on startup. It does not automatically replay historical database events to avoid inflating alert counters or generating duplicate alerts.
- Alert correlation keys (`fingerprint`) are persisted in SQLite with a partial unique constraint (`WHERE status IN ('open', 'acknowledged')`). If an alert was active before restart, newly triggered detections immediately correlate against the existing persisted alert record in SQLite.

---

## 5. Design Invariants & Fault Tolerance

- **Zero Unhandled Panics**: Production code paths prohibit `.unwrap()` and `.expect()`. Domain, collector, storage, and configuration errors propagate via `thiserror` and `Result`.
- **Unsafe Code Compartmentalization**: All unsafe C-FFI operations are confined exclusively to `sentinel-collector/src/windows_tcp.rs`. Domain model, detection rules, and storage strictly forbid unsafe code (`#![forbid(unsafe_code)]`).
- **No Blocking on Async Threads**: Native OS collection is offloaded to Tokio's blocking threadpool via `tokio::task::spawn_blocking`, keeping async reactor threads responsive.
- **Transactional Atomicity**: Event batches are inserted in discrete database transactions. Batches rollback completely on transient database errors.
- **Forensic Preservation**: Events linked to alerts are never purged by retention, guaranteeing relational integrity and auditability.
- **Graceful Termination**: The collection loop listens for OS shutdown signals (`tokio::signal::ctrl_c()`) and completes in-flight batch evaluation before reporting final summary statistics.
