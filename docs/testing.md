# Testing Strategy & Verification: SentinelX

## 1. Testing Philosophy

SentinelX implements a layered verification strategy to guarantee defensive stability, zero-panic execution, and mathematical invariants across all operational conditions.

```
       [ Integration Tests ]       End-to-end pipeline: collector -> normalize -> engine -> alerts
               ▲
       [ Property Tests ]          Invariants tested with proptest across arbitrary inputs
               ▲
       [ Unit Tests ]              Boundary conditions, byte-order conversions, and error variants
```

---

## 2. Test Suites Overview

### 2.1 Unit Tests

#### `sentinel-core`
- **`event::tests`**:
  - Valid construction via [`NetworkEventBuilder`](../crates/sentinel-core/src/event.rs).
  - Explicit rejection of invalid port 0 for source and destination ports.
  - Enforcement of [`EventMetadata`](../crates/sentinel-core/src/event.rs) entry count limits (16 entries) and byte size bounds.
  - JSON serialization and deserialization roundtrip parity.
- **`alert::tests`**:
  - Verification of valid [`SecurityAlert`](../crates/sentinel-core/src/alert.rs) generation.
  - Rejection of inverted time ranges (`first_observed_at > last_observed_at`).
  - Rejection of empty titles, empty explanations, and empty evidence lists.
  - Alert serde roundtrip across all severity levels and status enums.
- **`config::tests`**:
  - Verification that default parameters are valid.
  - Rejection of zero port threshold, zero window duration, negative window duration, zero batch size, and zero evidence limits.
  - Checked threshold arithmetic overflow detection.

#### `sentinel-collector`
- **`normalize::tests`**:
  - `test_ipv4_and_port_byte_order_decoding`: Validates network byte order (big-endian) integer decoding for IPv4 addresses and TCP ports.
  - `test_ipv6_normalization`: Verifies correct byte copying and string representation for IPv6 addresses.
  - `test_listening_socket_skipped`: Verifies that sockets in `TcpState::Listen` or sockets with `remote_port == 0` are skipped with `SkipReason::ListeningSocket`.
  - `test_invalid_local_port_zero`: Asserts that `local_port == 0` is rejected with `SkipReason::InvalidLocalPort`.
  - `test_normalize_established_record`: Asserts complete mapping of valid records into `NetworkEvent` with process ID and TCP state metadata.
- **`mock::tests`**:
  - `test_mock_port_sweep_scenario`: Verifies that `MockScenario::PortSweep` generates a deterministic multi-port sweep sequence.
  - `test_mock_mixed_scenario_skips_listening`: Validates that `MockScenario::Mixed` produces both normal events and skipped listening sockets.
  - `test_mock_sequence_progression`: Validates multi-batch sequence rotation.
  - `test_mock_injected_failure`: Validates that simulated collection errors cleanly return `CollectorError::MockFailure` without panic.
- **`stats::tests`**:
  - `test_stats_recording`: Validates tracking of attempted cycles, successful cycles, failure counts, raw counts, normalized counts, skipped counts, alert counts, and duration metrics.
- **`windows_tcp::tests`**:
  - `test_windows_tcp_collector_creation`: Verifies constructor and default naming.
  - `test_native_windows_collection_live`: **(Windows 11 Live Test)** Queries `GetExtendedTcpTable` directly against the local host TCP stack and asserts that records are successfully enumerated without administrator privileges.

#### `sentinel-detection`
- **`rules::port_scan::tests`**:
  - Detection trigger when distinct destination ports >= threshold.
  - Duplicate port invariance: repeated connections to the same port do not inflate count.
  - Source IP isolation: observations from distinct hosts are never merged.
  - Graceful handling of incomplete telemetry (events missing IP or port).
  - Evidence list bounding: evidence IDs capped at `max_evidence_ids_per_alert`.
  - Severity scaling verification (`Medium`, `High`, `Critical`).
- **`engine::tests`**:
  - Empty batch processing returns empty alerts without error.
  - Ingestion batch exceeding `max_batch_size` is rejected with `BatchSizeExceeded`.
  - Multi-rule orchestration with deterministic alert sorting.

---

### 2.2 Property-Based Tests (`proptest`)

Property-based tests evaluate fundamental invariants across thousands of randomized inputs:

| Suite | Invariant Tested | Guarantee |
| :--- | :--- | :--- |
| **`sentinel-core/tests/property_tests.rs`** | `prop_network_event_valid_ports` | Any valid IPv4 address and non-zero port (1..=65535) produces a valid `NetworkEvent`. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_network_event_zero_port_rejected` | Port 0 is **always** rejected for source or destination ports. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_metadata_bounds_check` | Metadata entries exceeding key or value byte bounds are strictly rejected. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_process_id_validation` | Operating system PIDs beyond `MAX_PROCESS_ID` (4,194,304) are rejected. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_alert_inverted_time_rejected` | Any alert with `first > last` is rejected. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_config_arithmetic_overflow` | Any threshold that would overflow `u16` when scaled fails configuration validation. |
| **`sentinel-collector/tests/property_tests.rs`** | `prop_ipv4_decoding_roundtrip` | Every `u32` decoded as network-order IPv4 preserves its byte representation. |
| **`sentinel-collector/tests/property_tests.rs`** | `prop_port_decoding_roundtrip` | Every 16-bit port decoded in network byte order roundtrips losslessly. |
| **`sentinel-collector/tests/property_tests.rs`** | `prop_listening_socket_always_skipped` | Sockets with `state == Listen` or `remote_port == 0` are **always** rejected with `ListeningSocket`. |
| **`sentinel-collector/tests/property_tests.rs`** | `prop_valid_records_always_normalize` | Any record with valid non-zero ports and non-listening state always yields a valid `NetworkEvent`. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_duplicate_ports_never_inflate_distinct_count` | Arbitrary repeated connections to an already observed port never trigger an alert if distinct ports < threshold. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_input_permutation_invariance` | Shuffling/permuting the input event sequence produces logically identical alerts. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_independent_source_ips_never_merged` | Independent source IPs never contaminate each other's distinct port counts. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_empty_input_produces_zero_alerts` | Empty input always produces exactly 0 alerts and never panics. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_evaluation_idempotency` | Evaluating identical inputs multiple times produces equivalent alert outputs. |

---

### 2.3 Integration Tests

#### 1. Detection Engine Integration (`tests/detection_integration.rs`)
Tests multi-category synthetic data through the analytical rule engine.

#### 2. Mock Collector Pipeline Integration (`tests/mock_integration.rs`)
Tests the full Phase 2 pipeline:
1. Instantiates `MockCollector` configured with `MockScenario::PortSweep`.
2. Collects a batch of raw records.
3. Normalizes records into `NetworkEvent` objects, asserting skipped counts.
4. Feeds normalized events into `DetectionEngine` with `PortScanRule` (`NET-001`).
5. Asserts that an alert is generated matching expected severity and evidence bounds.
6. Asserts that `MockScenario::Empty` cleanly produces 0 alerts without errors.

---

## 3. Reproduction Commands

### Run Full Test Suite (All Crates & Integration Tests)
```powershell
cargo test --workspace
```

### Run Mock Integration Tests Only
```powershell
cargo test --test mock_integration
```

### Run Detection Integration Tests Only
```powershell
cargo test --test detection_integration
```

### Run Collector Property Tests
```powershell
cargo test -p sentinel-collector --test property_tests
```

### Run Live Windows TCP Tests
```powershell
cargo test -p sentinel-collector -- windows_tcp::tests::test_native_windows_collection_live --nocapture
```

### Code Formatting and Clippy Lints
```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```
