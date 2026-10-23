# Architecture Overview: SentinelX

## 1. Architectural Mission

SentinelX is designed to deliver a modular, robust, and explainable defensive cybersecurity monitoring framework written in Rust.

The system decouples data acquisition, normalized domain representations, analytical detection logic, persistence, and user interfaces into distinct architectural boundaries.

---

## 2. Workspace Crate Separation

SentinelX is structured as a virtual Cargo workspace containing three decoupled crates:

```
crates/
├── sentinel-core/          # Pure domain models, validation, errors, config
├── sentinel-detection/     # Pluggable detection rules and analytical engine
└── sentinel-app/           # Demonstration CLI orchestration and reporting
```

### Dependency Graph

```
[ sentinel-app ]
       │
       ├─────────────────────────┐
       ▼                         ▼
[ sentinel-detection ] ───► [ sentinel-core ]
```

### Crate Responsibilities

#### `sentinel-core`
- **Role**: Pure domain kernel.
- **Dependencies**: Minimal external crates (`serde`, `serde_json`, `chrono`, `uuid`, `thiserror`). No I/O, no network bindings, no database drivers.
- **Components**:
  - `event`: [`NetworkEvent`](../crates/sentinel-core/src/event.rs), [`EventId`](../crates/sentinel-core/src/event.rs), [`NetworkProtocol`](../crates/sentinel-core/src/event.rs), [`TelemetrySource`](../crates/sentinel-core/src/event.rs), bounded [`EventMetadata`](../crates/sentinel-core/src/event.rs).
  - `alert`: [`SecurityAlert`](../crates/sentinel-core/src/alert.rs), [`AlertId`](../crates/sentinel-core/src/alert.rs), [`RuleId`](../crates/sentinel-core/src/alert.rs), [`AlertSeverity`](../crates/sentinel-core/src/alert.rs), [`AlertStatus`](../crates/sentinel-core/src/alert.rs).
  - `config`: [`DetectionConfig`](../crates/sentinel-core/src/config.rs) and threshold validation.
  - `error`: Strongly typed [`DomainError`](../crates/sentinel-core/src/error.rs) and [`ConfigError`](../crates/sentinel-core/src/error.rs).

#### `sentinel-detection`
- **Role**: Analytical detection engine.
- **Dependencies**: Depends strictly on `sentinel-core` and diagnostic `tracing`.
- **Components**:
  - `engine`: [`DetectionEngine`](../crates/sentinel-detection/src/engine.rs) orchestrating batch evaluation, bounding batch sizes, and guaranteeing deterministic sorting.
  - `rules`: Pluggable [`DetectionRule`](../crates/sentinel-detection/src/engine.rs) trait and concrete [`PortScanRule`](../crates/sentinel-detection/src/rules/port_scan.rs) (`NET-001`).

#### `sentinel-app`
- **Role**: Application orchestration and command-line demonstration.
- **Dependencies**: Orchestrates `sentinel-core` and `sentinel-detection`, initializes `tracing-subscriber`, handles application-level context via `anyhow`.

---

## 3. Extensibility & Future Phase Alignment

The Phase 1 architecture directly prepares for future expansion without requiring rewrites of the core analytical engine:

### 3.1 Windows Telemetry Ingestion (Phase 2)
In Phase 2, a dedicated telemetry collector crate (e.g., `sentinel-collector-windows`) will query the Windows IP Helper API via `GetExtendedTcpTable` or Event Tracing for Windows (ETW).
- The collector will normalize raw Windows socket records into `sentinel-core::NetworkEvent` structures with source `TelemetrySource::WindowsTcpSnapshot`.
- The `DetectionEngine` in `sentinel-detection` consumes these normalized events without knowing whether they originated from synthetic generators, ETW, or live socket tables.

### 3.2 Persistent Storage & Migrations (Phase 2)
In Phase 2, a persistence crate (e.g., `sentinel-storage`) will store `NetworkEvent` records and `SecurityAlert` instances in SQLite using schema migrations.
- Strongly typed newtypes (`EventId`, `AlertId`, `RuleId`) serialize transparently into UUID strings, matching database column schemas.
- Sliding time-window states across multi-batch observations will be backed by SQLite indices.

### 3.3 Tauri Desktop Dashboard (Phase 3)
In Phase 3, a desktop user interface built with Tauri 2 and React will interface with SentinelX.
- Tauri IPC commands will invoke the detection engine and storage crate.
- Serialized `SecurityAlert` JSON payloads flow cleanly across IPC boundaries into web visualization dashboards.

---

## 4. Design Invariants & Fault Tolerance

- **Zero Unhandled Panics**: Production code paths prohibit `.unwrap()` and `.expect()`. Domain errors and configuration mistakes are propagated via `thiserror` and `Result`.
- **Bounded Resource Utilization**: Batches exceeding `max_batch_size` are rejected before processing. Metadata entries and evidence collections enforce strict upper bounds to prevent memory denial-of-service.
- **Deterministic Evaluation**: Event grouping and alert emissions use ordered `BTreeMap` and deterministic sorting (`(source_ip, rule_id, timestamp, alert_id)`) ensuring identical outputs across diverse platforms.
