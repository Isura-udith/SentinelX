# Architecture Overview: SentinelX

## 1. Architectural Mission

SentinelX delivers a modular, robust, and explainable defensive cybersecurity monitoring framework written in Rust.

The system decouples data acquisition, normalized domain representations, analytical detection logic, asynchronous scheduling, persistence, and user interfaces into distinct architectural boundaries.

---

## 2. Workspace Crate Separation

SentinelX is structured as a virtual Cargo workspace containing four decoupled crates:

```
crates/
├── sentinel-core/          # Pure domain models, validation, errors, config
├── sentinel-collector/     # Telemetry collectors (Windows TCP snapshots & deterministic mock)
├── sentinel-detection/     # Pluggable detection rules and analytical engine
└── sentinel-app/           # Asynchronous orchestration, CLI execution, and reporting
```

### Dependency Graph

```
                   [ sentinel-app ]
                     │          │
         ┌───────────┘          └───────────┐
         ▼                                  ▼
[ sentinel-collector ]             [ sentinel-detection ]
         │                                  │
         └──────────────────┬───────────────┘
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
  - `mock`: [`MockCollector`](../crates/sentinel-collector/src/mock.rs) providing deterministic, reproducible fixtures (port sweep, repeated connections, normal traffic, mixed, empty, and simulated failure injection) for tests and cross-platform development.
  - `normalize`: [`RawTcpRecord`](../crates/sentinel-collector/src/normalize.rs), [`TcpState`](../crates/sentinel-collector/src/normalize.rs), [`normalize_tcp_record`](../crates/sentinel-collector/src/normalize.rs), byte-order decoding, and explicit listening socket skip filtering.
  - `stats`: [`CollectionStats`](../crates/sentinel-collector/src/stats.rs) tracking cycles, records observed, events normalized, records skipped, and collection latency.
  - `error`: Strongly typed [`CollectorError`](../crates/sentinel-collector/src/error.rs).

#### `sentinel-detection`
- **Role**: Analytical detection engine (`#![forbid(unsafe_code)]`).
- **Dependencies**: Depends strictly on `sentinel-core` and diagnostic `tracing`.
- **Components**:
  - `engine`: [`DetectionEngine`](../crates/sentinel-detection/src/engine.rs) orchestrating batch evaluation, bounding batch sizes, and guaranteeing deterministic sorting.
  - `rules`: Pluggable [`DetectionRule`](../crates/sentinel-detection/src/engine.rs) trait and concrete [`PortScanRule`](../crates/sentinel-detection/src/rules/port_scan.rs) (`NET-001`).

#### `sentinel-app`
- **Role**: Application orchestration and command-line execution.
- **Dependencies**: Orchestrates `sentinel-core`, `sentinel-collector`, `sentinel-detection`, Tokio runtime (`macros`, `rt-multi-thread`, `time`, `signal`), `tracing-subscriber`, and `anyhow`.
- **Components**:
  - `telemetry`: [`TelemetryScheduler`](../crates/sentinel-app/src/telemetry.rs) running asynchronous polling loops, isolating blocking FFI collection via `tokio::task::spawn_blocking`, handling graceful shutdown on `Ctrl+C`, and updating collection statistics.
  - `main`: CLI entry point supporting `--mock`, `--interval-ms`, `--max-cycles`, `--continuous`, and formatted diagnostic reporting.

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
  [ TelemetryScheduler (Tokio) ]
  - Bounded polling interval (>= 100ms)
  - Non-blocking execution (spawn_blocking)
  - Record cycle latency and counter stats
                │
                │ Batch of Normalized Events
                ▼
  [ DetectionEngine ]
  - Validate batch size bounds
  - Run registered rules (NET-001 PortScanRule)
  - Group by source IP, evaluate distinct port threshold
  - Bound evidence event IDs
                │
                │ Vec<SecurityAlert>
                ▼
  [ Structured Reporting / Analyst Triage ]
  - Formatted alert output with explainability context
  - Execution summary statistics table
```

---

## 4. Design Invariants & Fault Tolerance

- **Zero Unhandled Panics**: Production code paths prohibit `.unwrap()` and `.expect()`. Domain, collector, and configuration errors propagate via `thiserror` and `Result`.
- **Unsafe Code Compartmentalization**: All unsafe C-FFI operations are confined exclusively to `sentinel-collector/src/windows_tcp.rs`. Domain model and detection rules strictly forbid unsafe code.
- **No Blocking on Async Threads**: Native OS collection is offloaded to Tokio's blocking threadpool via `tokio::task::spawn_blocking`, keeping async reactor threads responsive.
- **Bounded Resource Utilization**: Batches exceeding `max_batch_size` are rejected. Intervals below 100 ms are rejected.
- **Graceful Termination**: The collection loop listens for OS shutdown signals (`tokio::signal::ctrl_c()`) and completes in-flight batch evaluation before reporting final summary statistics.
