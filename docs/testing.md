# Testing Strategy & Verification: SentinelX

## 1. Testing Philosophy

SentinelX implements a layered verification strategy to guarantee defensive stability, zero-panic execution, and mathematical invariants across all operational conditions.

```
       [ Integration Tests ]       End-to-end pipeline: events -> validation -> engine -> alerts
               ▲
       [ Property Tests ]          Invariants tested with proptest across arbitrary inputs
               ▲
       [ Unit Tests ]              Boundary conditions, serialization, and error variants
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
| **`sentinel-detection/tests/property_tests.rs`** | `prop_duplicate_ports_never_inflate_distinct_count` | Arbitrary repeated connections to an already observed port never trigger an alert if distinct ports < threshold. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_input_permutation_invariance` | Shuffling/permuting the input event sequence produces logically identical alerts. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_independent_source_ips_never_merged` | Independent source IPs never contaminate each other's distinct port counts. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_empty_input_produces_zero_alerts` | Empty input always produces exactly 0 alerts and never panics. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_evaluation_idempotency` | Evaluating identical inputs multiple times produces equivalent alert outputs. |

---

### 2.3 Integration Tests (`tests/detection_integration.rs`)

The integration test exercises the full analytical workflow:
1. Instantiates a `DetectionEngine` with `PortScanRule` (`NET-001`).
2. Ingests a multi-category synthetic dataset:
   - A port sweep scanner targeting 8 distinct ports (`192.0.2.10`).
   - A normal web browsing client targeting 2 ports (`192.0.2.50`).
   - A repetitive polling client targeting 1 port 12 times (`198.51.100.25`).
   - Incomplete telemetry events missing source IP or destination port (`198.51.100.99`).
3. Executes batch detection.
4. Asserts that exactly one alert is generated (for the scanner IP) with expected attributes (`Medium` severity, 8 evidence IDs).
5. Validates full JSON serialization and deserialization roundtrip.

---

## 3. Reproduction Commands

### Run Full Test Suite
```powershell
cargo test --workspace
```

### Run Integration Test Only
```powershell
cargo test --test detection_integration
```

### Run Property Tests Only
```powershell
cargo test --test property_tests
```

### Run Clippy Strict Verification
```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

### Run Format Check
```powershell
cargo fmt --all -- --check
```
