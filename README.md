# SentinelX

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%2011-blue.svg)]()

SentinelX is a modular, high-performance Rust defensive cybersecurity monitoring platform designed to analyze network connection telemetry, detect suspicious behaviors, and generate explainable, evidence-backed security alerts.

Built as an advanced systems engineering and security architecture portfolio project, SentinelX demonstrates strict memory safety, zero-panic defensive coding, deterministic analytical engines, property-based verification, and enterprise-grade modular design.

> **Operational Notice**:
> In Phase 1, SentinelX operates exclusively with deterministic synthetic data to validate domain models, rules, and engine mechanics. It requires **no administrator privileges** and collects **no real network traffic**.

---

## Table of Contents

- [Core Principles](#core-principles)
- [Architecture Overview](#architecture-overview)
- [Crate Structure](#crate-structure)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Running Tests](#running-tests)
- [Example Output](#example-output)
- [Documentation Index](#documentation-index)
- [Current Limitations](#current-limitations)
- [Roadmap & Future Milestones](#roadmap--future-milestones)
- [Security & Scope](#security--scope)
- [License](#license)

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
                                     v
                      +-----------------------------+
                      |      sentinel-detection     |
                      |  - DetectionEngine          |
                      |  - DetectionRule Trait      |
                      |  - PortScanRule (NET-001)   |
                      +--------------+--------------+
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

SentinelX is organized as a Cargo virtual workspace:

| Crate | Directory | Purpose |
| :--- | :--- | :--- |
| **`sentinel-core`** | `crates/sentinel-core` | Core domain models (`NetworkEvent`, `SecurityAlert`), strongly typed IDs (`EventId`, `AlertId`, `RuleId`), configuration (`DetectionConfig`), and domain errors. |
| **`sentinel-detection`** | `crates/sentinel-detection` | Analytical detection engine (`DetectionEngine`), extensible rule interface (`DetectionRule`), and `NET-001` port sweep rule. |
| **`sentinel-app`** | `crates/sentinel-app` | Command-line demonstration application generating deterministic synthetic scenarios and presenting structured reports. |

---

## Technology Stack

- **Language**: Rust (Stable channel, Edition 2024)
- **Serialization**: `serde`, `serde_json`
- **Time & Timestamps**: `chrono` (UTC)
- **Unique Identifiers**: `uuid` (v4 UUIDs)
- **Error Handling**: `thiserror` (domain errors), `anyhow` (application boundary context)
- **Logging & Diagnostics**: `tracing`, `tracing-subscriber` (with `RUST_LOG` filtering)
- **Testing**: Built-in test harness and `proptest` for property-based invariant verification

---

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain, 1.85+)
- Windows 11 (or any major OS for testing Phase 1 synthetic logic)
- Standard Cargo build tools

---

## Quick Start

### 1. Build the Entire Workspace

```powershell
cargo build --workspace
```

### 2. Run the Demonstration CLI

```powershell
cargo run -p sentinel-app
```

To run with verbose diagnostic tracing:

```powershell
$env:RUST_LOG="debug"; cargo run -p sentinel-app
```

---

## Running Tests

SentinelX includes comprehensive unit tests, property-based tests, and integration tests across all workspace crates.

### Run All Workspace Tests

```powershell
cargo test --workspace
```

### Run Integration Tests Specifically

```powershell
cargo test --test detection_integration
```

### Code Formatting and Clippy Lints

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## Example Output

```text
================================================================================
                           SENTINELX DEFENSIVE MONITOR                          
                Phase 1: Foundation and Domain Model Demonstration              
================================================================================
 Operational Notice:
 * ALL INPUT DATA IS ENTIRELY SYNTHETIC FOR DEMONSTRATION PURPOSES.
 * Documentation test address ranges (192.0.2.0/24, 198.51.100.0/24) are used.
 * No real network sockets are monitored; administrator rights are not needed.
================================================================================

2026-10-23T10:43:14.785412Z  INFO Initializing SentinelX detection engine with demonstration configuration...
2026-10-23T10:43:14.785536Z  INFO Registering detection rule rule_id=NET-001 rule_name=Port-Scan-Like Activity Detection
2026-10-23T10:43:14.785577Z  INFO Generating deterministic synthetic network connection observations...
2026-10-23T10:43:14.785611Z  INFO Synthetic dataset generated successfully total_observations=28
2026-10-23T10:43:14.785621Z  INFO Executing detection engine across event batch...
2026-10-23T10:43:14.785900Z  INFO process_batch: Batch processing finished successfully total_alerts=1 event_count=28
2026-10-23T10:43:14.785959Z  INFO Batch processing complete total_alerts=1

--------------------------------------------------------------------------------
                              EXECUTION SUMMARY                                 
--------------------------------------------------------------------------------
Total observations processed : 28
Total security alerts emitted: 1
--------------------------------------------------------------------------------

Generated Security Alerts:

[Alert #1]
  Alert ID           : 73720514-ea7a-4578-b2ac-2453d6eafaa2
  Rule ID            : NET-001
  Severity           : HIGH
  Title              : Port-Scan-Like Activity from 192.0.2.10 (12 distinct destination ports)
  Source Address     : 192.0.2.10
  Supporting Events  : 12
  Evidence IDs Count : 12
  Time Range (UTC)   : 2026-10-23 10:43:14.785584800 UTC -> 2026-10-23 10:43:16.435584800 UTC
  Triage Status      : OPEN
  Explanation        :
    Source IP 192.0.2.10 was observed contacting 12 distinct destination ports (threshold: 5) across 12 total connection observations. Sampled target ports: [21, 22, 23, 25, 53, 80, 110, 143 and 4 more]. Note: This alert constitutes a detection signal for analyst review. Legitimate network scanners, diagnostic tools, or multi-port service communications can cause similar telemetry patterns.

================================================================================
 Demonstration completed successfully without errors.
================================================================================
```

---

## Documentation Index

- [Architecture Overview](docs/architecture.md): Crate boundaries, dependency graphs, and Phase 2 integration hooks.
- [Domain Model Specification](docs/domain-model.md): Detailed schemas for `NetworkEvent`, `SecurityAlert`, `DetectionConfig`, validation rules, and lifecycle states.
- [Detection Rules Guide](docs/detection-rules.md): Specification of `NET-001`, threshold calculation, false-positive scenarios, and operational guidance.
- [Testing Guide](docs/testing.md): Automated testing framework, property-based invariants, and reproduction instructions.
- [Security Policy](SECURITY.md): Scope, vulnerability reporting, and threat model boundaries.

---

## Current Limitations

1. **In-Memory Batch Window**: Detection rule `NET-001` currently evaluates events within discrete batches rather than a persistent sliding rolling window.
2. **Synthetic Telemetry Only**: Phase 1 includes no live Windows socket pollers (`GetExtendedTcpTable`), Event Tracing for Windows (ETW), or packet sniffers.
3. **Volatile Storage**: Alerts and events reside entirely in memory; database persistence is scheduled for Phase 2.
4. **Demonstration Thresholds**: Default thresholds are configured for quick lab demonstration, not real-world production networks.

---

## Roadmap & Future Milestones

- **Phase 2 (Telemetry & Persistence)**:
  - Windows TCP connection snapshot collector (`GetExtendedTcpTable`).
  - SQLite event and alert persistence using migration scripts.
  - Rolling sliding-window state tracking across sampling batches.
- **Phase 3 (Desktop UI & Visualization)**:
  - Tauri 2 desktop application.
  - React/TypeScript analyst dashboard with real-time graphs and triage controls.
- **Phase 4 (Advanced Correlation Rules)**:
  - High-frequency connection churn / beaconing detection (`NET-002`).
  - Rare outbound process-to-port binding alerts (`HST-001`).

---

## Security & Scope

SentinelX is strictly a defensive telemetry analysis framework. For full details on our threat model and security boundaries, see [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
