# Testing Strategy & Verification: SentinelX

## 1. Testing Philosophy

SentinelX implements a layered verification strategy to guarantee defensive stability, zero-panic execution, and mathematical invariants across all operational conditions.

```
       [ Integration Tests ]       End-to-end pipeline: collector -> storage -> detection -> correlation -> alerts
               ▲
       [ Property Tests ]          Invariants tested with proptest across arbitrary inputs
               ▲
       [ Unit Tests ]              Storage repositories, migrations, rolling windows, and boundary conditions
```

---

## 2. Test Suites Overview

### 2.1 Database & Storage Integration Tests (`tests/storage_integration.rs`)

Tests verify SQLite persistence, transactional guarantees, and repository interfaces against temporary on-disk SQLite databases:

1. **`test_database_init_and_migrations`**: Verifies schema migration execution, table creation, and connection pooling.
2. **`test_foreign_key_enforcement`**: Verifies that SQLite foreign keys are enforced; attempting to insert an `alert_events` link referencing a non-existent `event_id` fails with a constraint violation.
3. **`test_batch_event_insertion_and_query`**: Verifies transactional batch insertion of normalized events, retrieval by ID, and total count.
4. **`test_idempotent_event_insertion`**: Verifies that inserting duplicate events with identical `EventId` succeeds idempotently without inflating count or erroring (`INSERT OR IGNORE`).
5. **`test_transaction_rollback_on_failure`**: Verifies transactional atomicity by executing a batch in a transaction; rolling back leaves the table completely untouched.
6. **`test_alert_creation_and_evidence_linking`**: Verifies alert persistence, query by ID, and linking supporting events in `alert_events`.
7. **`test_alert_correlation_upsert`**: Verifies `upsert_correlated_alert`: repeated alerts with the same fingerprint update `last_seen`, increment `event_count`, and attach new evidence IDs.
8. **`test_alert_status_transitions_and_audit`**: Verifies valid status transitions (`Open` → `Acknowledged` → `Resolved`), records audit log entries, and rejects invalid backwards transitions (`Resolved` → `Open`) with `StorageError::InvalidStatusTransition`.
9. **`test_database_reopening_persistence`**: Asserts that events and alerts persist cleanly across connection pool closes and reopenings.
10. **`test_retention_cleanup_preserves_evidence`**: Validates **Strategy A** retention: deletes expired events older than retention cutoff, but **preserves** events linked to alerts in `alert_events`.

---

### 2.2 End-to-End Pipeline Integration Tests (`tests/detection_pipeline.rs`)

Tests the complete operational lifecycle:
1. Instantiates temporary file-backed SQLite database.
2. Generates telemetry using `MockCollector` configured with `MockScenario::PortSweep`.
3. Normalizes raw TCP records into `NetworkEvent` objects.
4. Persists the batch transactionally via `EventRepository`.
5. Processes events through `DetectionEngine` with stateful `PortScanRule` (`NET-001`) and `ConnectionBurstRule` (`NET-002`).
6. Correlates and persists alerts via `AlertRepository::upsert_correlated_alert`.
7. Closes and reopens the database on an independent connection, verifying all alerts and evidence links survived.

---

### 2.3 Detection Unit & Stateful Rolling-Window Tests

#### `sentinel-detection`
- **`rules::port_scan::tests`**:
  - `test_distinct_port_threshold`: Fires alert when distinct destination ports >= threshold within the rolling window.
  - `test_duplicate_port_not_counted`: Repeated connections to the same port do not inflate the distinct port count.
  - `test_duplicate_event_id_ignored`: Duplicate event deliveries with identical `EventId` are ignored idempotently.
  - `test_source_ip_isolation`: Distinct source IPs maintain independent window state and never cross-contaminate.
  - `test_cooldown_suppression`: Subsequent alerts for the same source within the cooldown window are suppressed.
  - `test_old_event_pruned`: Events arriving outside the rolling window (`observed_at < watermark - window`) are pruned and do not trigger alerts.
  - `test_clock_skew_tolerance`: Events with future timestamps exceeding 5 minutes ahead of system clock are rejected.
  - `test_bounded_state_eviction`: When tracked sources exceed capacity, the oldest inactive source is evicted first.
- **`rules::connection_burst::tests`**:
  - `test_burst_threshold_trigger`: Alerts when observation count >= threshold within the sliding window.
  - `test_duplicate_events_ignored`: Deduplication by `EventId` ensures identical records are not double-counted.
  - `test_cooldown_suppression`: Enforces minimum interval between consecutive burst alerts.
  - `test_window_eviction`: Sliding window evicts expired observations when newer observations arrive.
  - `test_severity_scaling`: Scales severity from `Medium` to `High` and `Critical` as burst volume multiplies.

---

### 2.4 Property-Based Tests (`proptest`)

| Suite | Invariant Tested | Guarantee |
| :--- | :--- | :--- |
| **`sentinel-core/tests/property_tests.rs`** | `prop_network_event_valid_ports` | Valid IPv4 and non-zero ports produce valid `NetworkEvent`. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_network_event_zero_port_rejected` | Port 0 is **always** rejected for source or destination ports. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_metadata_bounds_check` | Metadata entries exceeding key or value byte bounds are strictly rejected. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_process_id_validation` | Operating system PIDs beyond `MAX_PROCESS_ID` (4,194,304) are rejected. |
| **`sentinel-core/tests/property_tests.rs`** | `prop_alert_inverted_time_rejected` | Any alert with `first > last` is rejected. |
| **`sentinel-collector/tests/property_tests.rs`** | `prop_ipv4_decoding_roundtrip` | Every `u32` decoded as network-order IPv4 preserves byte representation. |
| **`sentinel-collector/tests/property_tests.rs`** | `prop_port_decoding_roundtrip` | Every 16-bit port decoded in network byte order roundtrips losslessly. |
| **`sentinel-collector/tests/property_tests.rs`** | `prop_listening_socket_always_skipped` | Sockets with `state == Listen` or `remote_port == 0` are **always** skipped. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_duplicate_ports_never_inflate_distinct_count` | Repeated connections to an already observed port never trigger if distinct ports < threshold. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_input_permutation_invariance` | Shuffling the input event sequence produces logically identical alerts across fresh rule evaluators. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_independent_source_ips_never_merged` | Independent source IPs never contaminate each other's distinct port counts. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_empty_input_produces_zero_alerts` | Empty input always produces exactly 0 alerts and never panics. |
| **`sentinel-detection/tests/property_tests.rs`** | `prop_evaluation_idempotency` | Evaluating identical inputs on a fresh rule produces identical alerts. |

---

## 3. Reproduction Commands

### Run Full Test Suite (Workspace-wide, 74+ tests)
```powershell
cargo test --workspace
```

### Run Storage Integration Tests
```powershell
cargo test --test storage_integration
```

### Run Detection Pipeline Integration Tests
```powershell
cargo test --test detection_pipeline
```

### Run All Integration Tests
```powershell
cargo test --tests
```

### Run Code Formatting and Clippy Lints
```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Run SentinelX CLI with Mock Telemetry and Storage
```powershell
cargo run -p sentinel-app -- --mock --max-cycles 5 --db target/test_run.db
```
