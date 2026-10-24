# SentinelX

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%2011-blue.svg)]()

SentinelX is a modular, high-performance Rust defensive cybersecurity monitoring platform designed to collect local network connection telemetry, analyze connection behaviors, detect suspicious activities, persist forensic evidence, and generate explainable, evidence-backed security alerts.

Built as an advanced systems engineering and security architecture portfolio project, SentinelX demonstrates strict memory safety, zero-panic defensive coding, safe native Windows API integration, deterministic analytical engines, transactional SQLite persistence, stateful event-time rolling-window detection, alert correlation, property-based verification, and enterprise-grade modular design.

> **Operational Notice (Phase 3)**:
> SentinelX collects **point-in-time TCP connection table snapshots** via native Windows IP Helper APIs (`GetExtendedTcpTable`) in **read-only mode**.
> It operates with **standard user permissions** (no administrator rights needed), requires **no kernel or packet capture drivers**, and **neither modifies nor terminates network sockets**.
> Connection records and security alerts are durably persisted to a local **SQLite database** in Write-Ahead Logging (WAL) mode with embedded migrations and foreign-key integrity. A deterministic mock collector is provided for non-Windows development and automated testing.

---

## Table of Contents

- [Phase 3 Capabilities](#phase-3-capabilities)
- [Core Principles](#core-principles)
- [Architecture Overview](#architecture-overview)
- [Crate Structure](#crate-structure)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Quick Start & CLI Usage](#quick-start--cli-usage)
- [Database Schema & Persistence](#database-schema--persistence)
- [Detection Rules](#detection-rules)
- [Alert Correlation & Retention](#alert-correlation--retention)
- [Running Tests](#running-tests)
- [Example Output](#example-output)
- [Documentation Index](#documentation-index)
- [Known Limitations](#known-limitations)
- [Roadmap & Future Milestones](#roadmap--future-milestones)
- [Security & Scope](#security--scope)
- [License](#license)

---

## Phase 3 Capabilities

- **SQLite Persistence (`sentinel-storage`)**: Embedded version-controlled migrations (`0001_initial_schema.sql`, `0002_detection_indexes.sql`) utilizing SQLx with full foreign-key enforcement, 5-second busy timeout, and Write-Ahead Logging (WAL) mode.
- **Transactional Batched Ingestion**: Normalized telemetry is persisted in discrete, atomic database transactions with idempotent `EventId` collision handling (`INSERT OR IGNORE`).
- **Forensic Evidence Linking**: Connects security alerts to underlying evidence events through a dedicated `alert_events` mapping table.
- **Stateful Event-Time Rolling Windows**: Detection engine tracks observations across configurable sliding time windows using event observation timestamps (`observed_at`) rather than ingestion time, with duplicate `EventId` suppression and watermark-based window eviction.
- **Upgraded `NET-001` (Port Scan Detection)**: Distinct destination port counting within an event-time rolling window with bounded host tracking and cooldown suppression.
- **New `NET-002` (Connection Volume Anomaly)**: Connection burst heuristic identifying abnormal volume spikes from a single source within a sliding window.
- **Alert Fingerprinting & Correlation**: Merges repeated alerts for active incidents (`NET-001:{source_ip}`, `NET-002:{source_ip}`), advancing `last_seen`, incrementing observation counts, and appending new evidence links without creating duplicate alerts.
- **Audited Status Lifecycle**: Enforces validated status transitions (`Open` → `Acknowledged` → `Resolved`) and logs all triage and administrative actions to an immutable `audit_log` table.
- **Configurable Data Retention (Strategy A)**: Automated aging of raw events while strictly preserving any event referenced by an active or historical security alert.

---

## Core Principles

1. **Defensive Non-Interference**: SentinelX alerts represent reasoned hypotheses supported by observable telemetry. The engine **never** unilaterally terminates processes, blocks traffic, or modifies operating system state.
2. **Deterministic Processing**: Given the same sequence of observations and configuration, SentinelX produces identical alert outputs in stable, predictable order.
3. **Decoupled Architecture**: Domain models and detection rules are strictly isolated from concrete collectors, storage backends, and UI layers.
4. **Explicit Failure & Boundary Enforcement**: All configuration parameters, timestamps, port ranges, and metadata containers enforce checked arithmetic and strict bounded limits. Unbounded allocations and production panics (`unwrap()` / `expect()`) are forbidden.
5. **Relational Integrity**: Foreign-key enforcement is enabled across all connections. Supporting evidence records cannot be orphaned or deleted while linked to security alerts.

---

## Architecture Overview

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

---

## Crate Structure

SentinelX is organized as a Cargo virtual workspace containing five decoupled crates:

| Crate | Directory | Purpose |
| :--- | :--- | :--- |
| **`sentinel-core`** | `crates/sentinel-core` | Pure domain kernel (`#![forbid(unsafe_code)]`): models (`NetworkEvent`, `SecurityAlert`, `ProcessId`), identifiers, configuration, and domain errors. |
| **`sentinel-collector`** | `crates/sentinel-collector` | Telemetry subsystem: native Windows TCP snapshot collector (`GetExtendedTcpTable`), deterministic `MockCollector`, normalization, and statistics. |
| **`sentinel-detection`** | `crates/sentinel-detection` | Analytical detection engine (`#![forbid(unsafe_code)]`), stateful rolling-window tracking, `NET-001` port scan, and `NET-002` connection burst rules. |
| **`sentinel-storage`** | `crates/sentinel-storage` | SQLite persistence layer (`#![forbid(unsafe_code)]`): embedded SQLx migrations, WAL mode, transactional batch event insertion, alert correlation, and retention. |
| **`sentinel-app`** | `crates/sentinel-app` | Tokio asynchronous scheduler, command-line orchestration, pipeline coordinator, CLI options, and formatted summary reporting. |

---

## Technology Stack

- **Language**: Rust (Stable channel, Edition 2024)
- **Asynchronous Runtime**: `tokio` (macros, rt-multi-thread, time, sync, signal)
- **Database & Persistence**: `sqlx` (SQLite, runtime-tokio, chrono, uuid, migrate, macros)
- **Windows API**: `windows-sys` (`IpHelper`, `WinSock`, `Foundation`)
- **Serialization**: `serde`, `serde_json`
- **Time & Timestamps**: `chrono` (UTC)
- **Unique Identifiers**: `uuid` (v4 UUIDs)
- **Error Handling**: `thiserror` (typed domain, collector, & storage errors), `anyhow` (application context)
- **Logging & Diagnostics**: `tracing`, `tracing-subscriber` (with `RUST_LOG` filtering)
- **Testing**: Built-in test harness, temporary SQLite databases, and `proptest` for property-based invariant verification

---

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain, 1.85+)
- **Windows 11** (64-bit) for live native TCP table collection.
- *Cross-Platform Development*: Linux, macOS, or non-Windows hosts can build and run SentinelX using `--mock` mode and execute all platform-independent test suites.

---

## Quick Start & CLI Usage

### 1. Build the Entire Workspace

```powershell
cargo build --workspace
```

### 2. Launch Native Windows 11 Desktop Dashboard (Tauri 2)

Launches the SentinelX desktop window connecting React/TypeScript to the live backend:

```powershell
cargo run -p sentinel-app
```

### 3. Run Headless CLI Monitoring Mode

Useful for server deployments, background services, or automated scripting without GUI overhead:

```powershell
# Run 3 live Windows TCP collection cycles to SQLite:
cargo run -p sentinel-app -- --cli --max-cycles 3

# Run with deterministic mock telemetry scenario:
cargo run -p sentinel-app -- --cli --mock --max-cycles 5
```

### 4. Customizing Database Path, Intervals, and Retention

```powershell
# Specify a custom database path:
cargo run -p sentinel-app -- --db ./target/demo.db

# Run 5 collection cycles with 500ms intervals:
cargo run -p sentinel-app -- --interval-ms 500 --max-cycles 5 --db ./target/demo.db

# Run mock collector with custom retention window (7 days):
cargo run -p sentinel-app -- --mock --interval-ms 250 --max-cycles 10 --retention-days 7

# Run continuously without automated retention cleanup:
cargo run -p sentinel-app -- --continuous --no-retention
```

### 5. Viewing CLI Help

```powershell
cargo run -p sentinel-app -- --help
```

---

## Database Schema & Persistence

SentinelX manages a local SQLite database with embedded schema migrations:

- **`events`**: Normalized network connection observations (`id`, `observed_at`, `source`, `protocol`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `process_id`, `metadata_json`, `ingested_at`).
- **`alerts`**: Correlated security alerts (`id`, `rule_id`, `rule_version`, `severity`, `title`, `description`, `first_seen`, `last_seen`, `status`, `event_count`, `fingerprint`). A partial unique index enforces that at most one active alert (`status IN ('open', 'acknowledged')`) exists per fingerprint.
- **`alert_events`**: Relational junction table linking alerts to supporting event IDs with composite primary key and `ON DELETE RESTRICT`.
- **`audit_log`**: Immutable audit records tracking alert status changes and retention operations.
- **`detection_rules`**: Seed metadata catalog for analytical rules.

For full schema details, indexes, and queries, see [docs/database-schema.md](docs/database-schema.md).

---

## Detection Rules

| Rule ID | Rule Name | Category | Primary Dimensions | Window Semantics |
| :--- | :--- | :--- | :--- | :--- |
| **`NET-001`** | Port-Scan-Like Activity Detection | Reconnaissance | Source IP, Distinct Dest Ports | Event-Time Sliding Window |
| **`NET-002`** | Connection Volume Anomaly Detection | Anomaly / Burst | Source IP, Observation Count | Event-Time Sliding Window |

See [docs/detection-rules.md](docs/detection-rules.md) for detailed detection logic, false-positive baselines, and configuration parameters.

---

## Alert Correlation & Retention

- **Correlation**: Repeated detections for the same source within the active window match the stable fingerprint (`NET-001:{source_ip}`). Rather than emitting redundant alerts, SentinelX advances `last_seen`, increments `event_count`, and appends new supporting event IDs to `alert_events`.
- **Evidence Preservation (Strategy A)**: Expired events older than the retention threshold are safely pruned, **except** for any event referenced by `alert_events`. Supporting forensic evidence remains queryable indefinitely.

See [docs/retention-policy.md](docs/retention-policy.md) for full retention specifications.

---

## Running Tests

SentinelX includes 74 automated unit, property-based, mock integration, storage integration, and live Windows tests:

```powershell
# Run all workspace tests:
cargo test --workspace

# Run storage integration tests (SQLite, transactions, retention):
cargo test --test storage_integration

# Run end-to-end detection pipeline integration test:
cargo test --test detection_pipeline

# Run mock collector integration test:
cargo test --test mock_integration

# Run collector property-based tests:
cargo test -p sentinel-collector --test property_tests

# Run live Windows TCP collection test (queries OS directly):
cargo test -p sentinel-collector -- windows_tcp::tests::test_native_windows_collection_live --nocapture

# Check code formatting and strict Clippy lints:
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## Example Output

### Live Windows 11 Collection & Persistence Run

```text
================================================================================
                           SENTINELX DEFENSIVE MONITOR                          
            Phase 3: Storage, Persistence & Stateful Detection Engine          
================================================================================
 Operational Notice:
 * Telemetry Mode: LIVE WINDOWS TCP SNAPSHOT (IP Helper API).
 * Persistence: SQLite WAL Mode (Path: target/demo.db)
 * Querying native host TCP table via GetExtendedTcpTable in read-only mode.
 * No administrator privileges required; standard user permissions sufficient.
 * Network sockets are neither modified, redirected, nor terminated.
================================================================================

2026-10-24T00:15:20.128456Z  INFO Initializing SentinelX storage subsystem database_path="target/demo.db"
2026-10-24T00:15:20.142512Z  INFO Database migrations applied successfully
2026-10-24T00:15:20.143210Z  INFO Registering detection rule rule_id=NET-001 rule_name=Port-Scan-Like Activity Detection
2026-10-24T00:15:20.143320Z  INFO Registering detection rule rule_id=NET-002 rule_name=Connection Volume Anomaly Detection
2026-10-24T00:15:20.143510Z  INFO Starting telemetry collection and detection pipeline...
2026-10-24T00:15:20.151240Z  INFO --- Starting telemetry collection cycle --- cycle=1
2026-10-24T00:15:20.152110Z  INFO windows_tcp_collect: Native Windows TCP table collection completed raw_records=118 normalized_events=79 skipped_records=39 latency=890.4µs
2026-10-24T00:15:20.155420Z  INFO Batch persisted to SQLite batch_size=79 duration=3.31ms
2026-10-24T00:15:20.156180Z  INFO Security alert persisted alert_id=3c129e62-97b6-455b-bf9f-2da9bfcb9171 rule=NET-001 fingerprint="NET-001:127.0.0.1" correlated=false
2026-10-24T00:15:20.157890Z  INFO Pipeline metrics: events_ingested=79 alerts_created=1 alerts_correlated=0 retention_purges=0
2026-10-24T00:15:20.158120Z  INFO Configured maximum collection cycles completed cycle=1 max=1

--------------------------------------------------------------------------------
                              EXECUTION SUMMARY                                 
--------------------------------------------------------------------------------
Collection Statistics:
  Total Cycles Attempted   : 1
  Successful Cycles        : 1
  Failed Cycles            : 0
  Raw Records Observed     : 118
  Normalized Events        : 79
  Records Skipped          : 39
  Security Alerts Emitted  : 1
  Most Recent Cycle Latency: 890.4µs
--------------------------------------------------------------------------------

Pipeline & Storage Metrics:
  Events Ingested to DB    : 79
  Alerts Created           : 1
  Alerts Correlated        : 0
  Duplicate Events Ignored : 0
  Database Errors          : 0
  Retention Purges         : 0
--------------------------------------------------------------------------------

Generated Security Alerts (1):

[Alert #1]
  Alert ID           : 3c129e62-97b6-455b-bf9f-2da9bfcb9171
  Rule ID            : NET-001
  Severity           : CRITICAL
  Title              : Port-Scan-Like Activity from 127.0.0.1 (28 distinct destination ports)
  Source Address     : 127.0.0.1
  Supporting Events  : 41
  Evidence IDs Count : 20
  Triage Status      : OPEN
  Fingerprint        : NET-001:127.0.0.1
  Explanation        :
    Source IP 127.0.0.1 was observed contacting 28 distinct destination ports (threshold: 5) across 41 total connection observations. Sampled target ports: [53167, 53907, 53908, 54109 and 24 more].

================================================================================
 Phase 3 demonstration completed successfully without errors.
================================================================================
```

---

## Documentation Index

- [Architecture Overview](docs/architecture.md): Workspace crate decoupling, `sentinel-storage`, `TelemetryCollector` trait, and pipeline coordinator.
- [Database Schema Specification](docs/database-schema.md): Full documentation of SQLite tables, indexes, constraints, and embedded migrations.
- [Data Retention Policy](docs/retention-policy.md): Specification of retention windows, evidence preservation guarantees, and batched cleanup.
- [Detection Rules Guide](docs/detection-rules.md): Specification of `NET-001` and `NET-002`, rolling-window semantics, threshold calculation, and false-positive baselines.
- [Testing Guide](docs/testing.md): Automated testing framework, integration test suites, property-based invariants, and reproduction instructions.
- [Security Architecture](docs/security.md): Least privilege design, non-invasive guarantees, standard-user permissions, and input bounding.
- [Security Policy](SECURITY.md): Vulnerability reporting, database security, and SQL injection prevention.
- [Domain Model Specification](docs/domain-model.md): Detailed schemas for `NetworkEvent`, `SecurityAlert`, `DetectionConfig`, and validation rules.
- [Telemetry Specification](docs/telemetry.md): In-depth guide to Windows `GetExtendedTcpTable`, byte-order decoding, and TCP state mappings.

---

## Known Limitations

1. **Snapshot Sampling Heuristics**: Connections established and closed between polling intervals are not captured. `NET-002` operates as an observation volume heuristic because snapshot polling inherently resamples long-lived established connections.
2. **TCP-Only Telemetry**: UDP endpoints and ICMP messages are not captured by `GetExtendedTcpTable`.
3. **No Packet Payload Capture**: Telemetry contains connection metadata only (IP, port, PID, TCP state). Payload bytes and packet headers are not collected.
4. **Localhost IPC Signals**: Legitimate developer tools and microservices communicating over loopback (`127.0.0.1`) can trigger port sweep alerts if the threshold is configured below baseline usage.
5. **In-Memory Rolling Window Reset**: Detection rolling-window state is maintained in-memory for zero-latency evaluation and resets on application restart; historical alerts and evidence remain durable in SQLite.

---

## Roadmap & Future Milestones

- **Phase 1 (Foundation & Domain Model)**: *Completed*
  - Workspace structure, core domain types, detection engine, `NET-001` rule, property-based testing.
- **Phase 2 (Windows Telemetry)**: *Completed*
  - Native Windows IP Helper TCP snapshot collector (`GetExtendedTcpTable`).
  - Alignment-safe memory reads and endianness decoding.
  - Deterministic `MockCollector` and sequence rotation.
  - Tokio asynchronous scheduler with graceful shutdown and statistics tracking.
- **Phase 3 (Storage & Stateful Detection)**: *Completed*
  - SQLite persistence with SQLx and embedded schema migrations.
  - Transactional batched event insertion with idempotent deduplication.
  - Stateful event-time rolling-window analysis (`NET-001`, `NET-002`).
  - Alert fingerprinting, correlation, and evidence linking (`alert_events`).
  - Configurable retention with active forensic evidence preservation (Strategy A).
- **Phase 4 (Tauri Desktop Dashboard & Security Operations)**: *Completed*
  - Native Windows 11 desktop application via Tauri 2, React 19, TypeScript (strict mode), and Tailwind CSS.
  - Professional cybersecurity SOC dark theme with high contrast typography and accessible status indicators.
  - 7 global navigation pages: Overview, Network Events, Security Alerts, Detection Rules, Telemetry, Audit History, Settings.
  - 17 typed Rust backend commands with strict boundary validation and safe error mapping.
  - Server-side SQLite pagination and multi-parameter filtering for events and alerts.
  - Interactive alert triage with evidence inspection, status transitions (`Acknowledge`, `Resolve`), and audit trail.
  - Real-time IPC event notifications (`sentinel://*`) without busy polling.
  - Preservation of headless CLI monitoring mode (`--cli`).
- **Phase 5 (Advanced Telemetry & Correlation)**:
  - Windows ETW (Event Tracing for Windows) integration for real-time connection event streams.
  - UDP endpoint tracking via `GetExtendedUdpTable`.

---

## Security & Scope

SentinelX is strictly a defensive telemetry analysis framework. For full details on our threat model and security boundaries, see [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
