# SentinelX

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%2011-blue.svg)]()

SentinelX is a modular, high-performance Rust defensive cybersecurity monitoring platform designed to collect local network connection telemetry, analyze connection behaviors, detect suspicious activities, and generate explainable, evidence-backed security alerts.

Built as an advanced systems engineering and security architecture portfolio project, SentinelX demonstrates strict memory safety, zero-panic defensive coding, safe native Windows API integration, deterministic analytical engines, property-based verification, and enterprise-grade modular design.

> **Operational Notice (Phase 2)**:
> SentinelX collects **point-in-time TCP connection table snapshots** via native Windows IP Helper APIs (`GetExtendedTcpTable`) in **read-only mode**.
> It operates with **standard user permissions** (no administrator rights needed), requires **no kernel or packet capture drivers**, and **neither modifies nor terminates network sockets**. A deterministic mock collector is provided for non-Windows development and testing.

---

## Table of Contents

- [Phase 2 Features](#phase-2-features)
- [Core Principles](#core-principles)
- [Architecture Overview](#architecture-overview)
- [Crate Structure](#crate-structure)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Quick Start & CLI Usage](#quick-start--cli-usage)
- [Supported Telemetry Fields](#supported-telemetry-fields)
- [Running Tests](#running-tests)
- [Example Output](#example-output)
- [Documentation Index](#documentation-index)
- [Known Limitations](#known-limitations)
- [Roadmap & Future Milestones](#roadmap--future-milestones)
- [Security & Scope](#security--scope)
- [License](#license)

---

## Phase 2 Features

- **Native Windows TCP Snapshot Collection**: Queries the Windows IP Helper API (`GetExtendedTcpTable`) for IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) TCP connection tables with process ID attribution (`TCP_TABLE_OWNER_PID_ALL`).
- **Memory Safety & Unsafe Isolation**: Encapsulates Windows C-FFI operations strictly within `sentinel-collector`, using `std::ptr::read_unaligned` for alignment-safe memory copies and checked buffer bounds.
- **Byte-Order Decoding & Normalization**: Automatically decodes big-endian network byte order IP addresses and port numbers into strongly typed `sentinel-core::NetworkEvent` models.
- **Explicit Normalization Policies**: Detects and cleanly skips listening sockets (`TcpState::Listen` or `remote_port == 0`) while recording granular skip metrics.
- **Deterministic Mock Collector**: Provides in-memory test fixtures (`PortSweep`, `RepeatedPort`, `NormalTraffic`, `Mixed`, `Empty`, and simulated failure injection) without generating external network traffic.
- **Asynchronous Tokio Scheduler**: Drives non-blocking periodic polling using `tokio::time::interval`, offloading native FFI calls via `tokio::task::spawn_blocking`.
- **Runtime Collection Statistics**: Records total collection attempts, successes, failures, raw records observed, normalized events, records skipped, alert counts, and collection latencies.
- **Graceful Shutdown**: Traps OS termination signals (`Ctrl+C`) to finish in-flight batches cleanly and output an execution diagnostic summary.

---

## Core Principles

1. **Defensive Non-Interference**: SentinelX alerts represent reasoned hypotheses supported by observable telemetry. The engine **never** unilaterally terminates processes, blocks traffic, or modifies operating system state.
2. **Deterministic Processing**: Given the same sequence of observations and configuration, SentinelX produces identical alert outputs in stable, predictable order.
3. **Decoupled Architecture**: Domain models and detection rules are strictly isolated from concrete collectors, storage backends, and UI layers.
4. **Explicit Failure & Boundary Enforcement**: All configuration parameters, timestamps, port ranges, and metadata containers enforce checked arithmetic and strict bounded limits. Unbounded allocations and production panics (`unwrap()` / `expect()`) are forbidden.

---

## Architecture Overview

```
                   +-----------------------------+
                   |   sentinel-app (CLI Demo)   |
                   +--------------+--------------+
                                  |
         +------------------------+------------------------+
         |                                                 |
         v                                                 v
+-----------------------------+                   +-----------------------------+
|      sentinel-collector     |                   |      sentinel-detection     |
|  - TelemetryCollector Trait |                   |  - DetectionEngine          |
|  - WindowsTcpCollector      |                   |  - DetectionRule Trait      |
|  - MockCollector            |                   |  - PortScanRule (NET-001)   |
|  - Normalization & Stats    |                   +--------------+--------------+
+--------------+--------------+                                  |
               |                                                 |
               +------------------------+------------------------+
                                        |
                                        v
                         +-----------------------------+
                         |        sentinel-core        |
                         |  - NetworkEvent & EventId   |
                         |  - SecurityAlert & AlertId  |
                         |  - DetectionConfig          |
                         |  - DomainError & Invariants |
                         +-----------------------------+
```

---

## Crate Structure

SentinelX is organized as a Cargo virtual workspace containing four decoupled crates:

| Crate | Directory | Purpose |
| :--- | :--- | :--- |
| **`sentinel-core`** | `crates/sentinel-core` | Pure domain kernel (`#![forbid(unsafe_code)]`): models (`NetworkEvent`, `SecurityAlert`, `ProcessId`), identifiers, configuration, and domain errors. |
| **`sentinel-collector`** | `crates/sentinel-collector` | Telemetry subsystem: native Windows TCP snapshot collector (`GetExtendedTcpTable`), deterministic `MockCollector`, normalization, and statistics. |
| **`sentinel-detection`** | `crates/sentinel-detection` | Analytical detection engine (`#![forbid(unsafe_code)]`), pluggable rule interface (`DetectionRule`), and `NET-001` port sweep rule. |
| **`sentinel-app`** | `crates/sentinel-app` | Tokio asynchronous scheduler, command-line orchestration, CLI options, and formatted summary reporting. |

---

## Technology Stack

- **Language**: Rust (Stable channel, Edition 2024)
- **Asynchronous Runtime**: `tokio` (macros, rt-multi-thread, time, sync, signal)
- **Windows API**: `windows-sys` (`IpHelper`, `WinSock`, `Foundation`)
- **Serialization**: `serde`, `serde_json`
- **Time & Timestamps**: `chrono` (UTC)
- **Unique Identifiers**: `uuid` (v4 UUIDs)
- **Error Handling**: `thiserror` (typed domain & collector errors), `anyhow` (application context)
- **Logging & Diagnostics**: `tracing`, `tracing-subscriber` (with `RUST_LOG` filtering)
- **Testing**: Built-in test harness and `proptest` for property-based invariant verification

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

### 2. Run with Native Windows 11 Telemetry (Default)

Executes 3 collection cycles (1 snapshot per second) against your local host TCP table:

```powershell
cargo run -p sentinel-app
```

### 3. Run with Deterministic Mock Telemetry

Useful for testing, demonstrations, or non-Windows platforms without querying the live operating system:

```powershell
cargo run -p sentinel-app -- --mock
```

### 4. Customizing Interval and Cycles

```powershell
# Run 5 collection cycles with 500ms intervals:
cargo run -p sentinel-app -- --interval-ms 500 --max-cycles 5

# Run mock collector with 250ms polling:
cargo run -p sentinel-app -- --mock --interval-ms 250 --max-cycles 10

# Run continuously until Ctrl+C is pressed:
cargo run -p sentinel-app -- --continuous
```

### 5. Viewing CLI Help

```powershell
cargo run -p sentinel-app -- --help
```

---

## Supported Telemetry Fields

When querying Windows 11 TCP tables via `GetExtendedTcpTable`, SentinelX extracts and normalizes the following fields:

| Field | Source Type | Normalized Type | Description |
| :--- | :--- | :--- | :--- |
| `source_ip` | `dwLocalAddr` / `ucLocalAddr` | `std::net::IpAddr` | Local IP address (IPv4 or IPv6) |
| `source_port` | `dwLocalPort` | `u16` | Local TCP port (decoded from network byte order) |
| `destination_ip` | `dwRemoteAddr` / `ucRemoteAddr` | `std::net::IpAddr` | Remote IP address (IPv4 or IPv6) |
| `destination_port` | `dwRemotePort` | `u16` | Remote TCP port (decoded from network byte order) |
| `tcp_state` | `dwState` | `metadata["tcp_state"]` | Mapped TCP state (`Established`, `TimeWait`, `CloseWait`, etc.) |
| `process_id` | `dwOwningPid` | `Option<ProcessId>` | Operating system PID owning the socket |
| `protocol` | Static TCP | `NetworkProtocol::Tcp` | Protocol identifier |
| `source` | Static Collector | `TelemetrySource::WindowsTcpSnapshot` | Originating telemetry source |

---

## Running Tests

SentinelX includes 54 automated unit, property-based, mock integration, and live Windows tests:

```powershell
# Run all workspace tests:
cargo test --workspace

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

### Live Windows 11 Collection Run

```text
================================================================================
                           SENTINELX DEFENSIVE MONITOR                          
             Phase 2: Windows 11 Telemetry Subsystem & Detection Engine         
================================================================================
 Operational Notice:
 * Telemetry Mode: LIVE WINDOWS TCP SNAPSHOT (IP Helper API).
 * Querying native host TCP table via GetExtendedTcpTable in read-only mode.
 * No administrator privileges required; standard user permissions sufficient.
 * Network sockets are neither modified, redirected, nor terminated.
================================================================================

2026-10-23T11:39:40.483298Z  INFO Initializing SentinelX detection engine with demonstration threshold configuration...
2026-10-23T11:39:40.483444Z  INFO Registering detection rule rule_id=NET-001 rule_name=Port-Scan-Like Activity Detection
2026-10-23T11:39:40.483486Z  INFO Starting telemetry collection and detection pipeline...
2026-10-23T11:39:40.483499Z  INFO Starting SentinelX telemetry collection loop interval=100ms max_cycles=Some(1) collector=WindowsTcpCollector
2026-10-23T11:39:40.492549Z  INFO --- Starting telemetry collection cycle --- cycle=1
2026-10-23T11:39:40.493096Z  INFO windows_tcp_collect: Initiating native Windows TCP connection table snapshot
2026-10-23T11:39:40.494053Z  INFO windows_tcp_collect: Native Windows TCP table collection completed raw_records=121 normalized_events=82 skipped_records=39 latency=961.7µs
2026-10-23T11:39:40.494180Z  INFO Telemetry snapshot collected successfully raw=121 normalized=82 skipped=39 duration=961.7µs
2026-10-23T11:39:40.494343Z  INFO process_batch: Batch processing finished successfully total_alerts=1 event_count=82
2026-10-23T11:39:40.494394Z  WARN Security alerts generated during cycle alert_count=1
2026-10-23T11:39:40.494434Z  INFO Configured maximum collection cycles completed cycle=1 max=1
2026-10-23T11:39:40.494443Z  INFO Collection scheduler completed all cycles

--------------------------------------------------------------------------------
                              EXECUTION SUMMARY                                 
--------------------------------------------------------------------------------
Collection Statistics:
  Total Cycles Attempted   : 1
  Successful Cycles        : 1
  Failed Cycles            : 0
  Raw Records Observed     : 121
  Normalized Events        : 82
  Records Skipped          : 39
  Security Alerts Emitted  : 1
  Last Successful Cycle    : 2026-10-23T11:39:40.494176400+00:00
  Most Recent Cycle Latency: 961.7µs
--------------------------------------------------------------------------------

Generated Security Alerts (1):

[Alert #1]
  Alert ID           : 80ec3651-11d6-4e10-9009-a37d812166ee
  Rule ID            : NET-001
  Severity           : CRITICAL
  Title              : Port-Scan-Like Activity from 127.0.0.1 (29 distinct destination ports)
  Source Address     : 127.0.0.1
  Supporting Events  : 42
  Evidence IDs Count : 20
  Time Range (UTC)   : 2026-10-23 11:39:40.493077800 UTC -> 2026-10-23 11:39:40.493077800 UTC
  Triage Status      : OPEN
  Explanation        :
    Source IP 127.0.0.1 was observed contacting 29 distinct destination ports (threshold: 5) across 42 total connection observations. Sampled target ports: [53167, 53907, 53908, 54109, 54338, 54797, 54798, 54799 and 21 more]. Note: This alert constitutes a detection signal for analyst review. Legitimate network scanners, diagnostic tools, or multi-port service communications can cause similar telemetry patterns.

================================================================================
 Phase 2 demonstration completed successfully without errors.
================================================================================
```

---

## Documentation Index

- [Architecture Overview](docs/architecture.md): Workspace crate decoupling, `TelemetryCollector` trait, FFI isolation, and async scheduler pipeline.
- [Telemetry Specification](docs/telemetry.md): In-depth guide to Windows `GetExtendedTcpTable`, byte-order decoding, TCP state mappings, and snapshot collection limitations.
- [Security Architecture](docs/security.md): Least privilege design, non-invasive guarantees, standard-user permissions, unsafe isolation, and input bounding.
- [Domain Model Specification](docs/domain-model.md): Detailed schemas for `NetworkEvent`, `SecurityAlert`, `DetectionConfig`, validation rules, and lifecycle states.
- [Detection Rules Guide](docs/detection-rules.md): Specification of `NET-001`, threshold calculation, false-positive scenarios, and operational guidance.
- [Testing Guide](docs/testing.md): Automated testing framework, property-based invariants, and reproduction instructions.
- [Security Policy](SECURITY.md): Vulnerability reporting and scope boundaries.

---

## Known Limitations

1. **Snapshot Blindspots**: Connections established and torn down between polling intervals are not captured.
2. **TCP-Only Telemetry**: UDP endpoints and ICMP messages are not captured by `GetExtendedTcpTable`.
3. **No Packet Payload Capture**: Telemetry contains connection metadata only (IP, port, PID, TCP state). Payload bytes and packet headers are not collected.
4. **Repeated Observations of Long-Lived Connections**: Active established connections will appear in every consecutive snapshot cycle. Multi-batch deduplication is scheduled for Phase 3's persistence layer.
5. **Localhost IPC Signals**: Legitimate developer tools and microservices communicating over loopback (`127.0.0.1`) can trigger port sweep alerts if the threshold is configured below baseline usage.

---

## Roadmap & Future Milestones

- **Phase 1 (Foundation & Domain Model)**: *Completed*
  - Workspace structure, core domain types, detection engine, `NET-001` rule, property-based testing.
- **Phase 2 (Windows Telemetry)**: *Completed*
  - Native Windows IP Helper TCP snapshot collector (`GetExtendedTcpTable`).
  - Alignment-safe memory reads and endianness decoding.
  - Deterministic `MockCollector` and sequence rotation.
  - Tokio asynchronous scheduler with graceful shutdown and statistics tracking.
- **Phase 3 (Persistence & Sliding Window)**:
  - SQLite database backing for events and alerts with schema migrations.
  - Persistent sliding-window deduplication across polling intervals.
- **Phase 4 (Tauri Desktop UI & Visualization)**:
  - Tauri 2 desktop application with React / TypeScript dashboard.
  - Real-time connection graphs and alert triage workflows.
- **Phase 5 (Advanced Telemetry & Correlation)**:
  - Windows ETW (Event Tracing for Windows) integration for real-time connection event streams.
  - UDP endpoint tracking via `GetExtendedUdpTable`.

---

## Security & Scope

SentinelX is strictly a defensive telemetry analysis framework. For full details on our threat model and security boundaries, see [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
