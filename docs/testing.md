# Testing Strategy & Verification: SentinelX

## 1. Testing Philosophy

SentinelX implements a layered verification strategy to guarantee defensive stability, zero-panic execution, and mathematical invariants across all operational conditions.

```
       [ Failure Injection Tests ]  Component failures, lock contention, invalid inputs, error sanitization
               ▲
       [ Integration Tests ]        End-to-end pipeline: collector -> storage -> detection -> correlation -> alerts
               ▲
       [ Property Tests ]           Invariants tested with proptest across arbitrary inputs
               ▲
       [ Unit Tests ]               Storage repositories, migrations, rolling windows, and boundary conditions
```

---

## 2. Test Suites Overview

### 2.1 Failure Injection & Boundary Integration Tests (`tests/failure_injection.rs`)

Tests verify system resilience when subjected to abnormal conditions, malformed inputs, and injected failures:

1. **`test_database_config_validation_rejections`**:
   - Asserts that empty database paths, paths containing injected null bytes (`\0`), and configurations with `max_connections = 0` are rejected immediately prior to connection initialization.
2. **`test_audit_entry_boundary_validations`**:
   - Enforces length limits on `AuditEntry` fields (`MAX_AUDIT_ACTOR_LEN = 64`, `MAX_AUDIT_ACTION_LEN = 64`, `MAX_AUDIT_TARGET_TYPE_LEN = 64`, `MAX_AUDIT_TARGET_ID_LEN = 128`, `MAX_AUDIT_DETAILS_BYTES = 64 KB`).
   - Asserts that entries with clock skew exceeding 5 minutes into the future are rejected.
3. **`test_frontend_command_validation_rejections`**:
   - Asserts that Tauri command input validators reject oversized search strings (> 256 chars), malformed or oversized IP strings (> 64 chars), invalid rule IDs outside the allowlist, and note lengths exceeding 1024 characters.
4. **`test_collector_failure_injection_handling`**:
   - Injects simulated Windows API native failures via `MockCollector::inject_failure(CollectorError::NativeApiFailure)`.
   - Asserts that the pipeline coordinator records the error in telemetry stats without panicking, crashing, or falsely reporting collection success.
5. **`test_empty_telemetry_snapshot_handling`**:
   - Executes pipeline collection when the operating system returns zero established connections.
   - Asserts that the cycle completes cleanly, produces 0 events and 0 alerts, and reports `last_success` accurately.
6. **`test_invalid_alert_status_transitions_rejected`**:
   - Tests alert lifecycle transitions and asserts that invalid transitions (e.g., from `Resolved` back to `Open` without reopening semantics) are rejected transactionally.

---

### 2.2 Empirical Performance Benchmark Suite (`tests/benchmark_measurements.rs`)

Measures empirical throughput, latency, and resource limits under realistic synthetic workloads:
- **Database Initialization & SQLite Migrations**: Measures cold database startup and schema migration duration (< 20 ms).
- **Event Ingestion Throughput**: Tests batch ingestion of 5,000 synthetic events (target: >= 1,000 events/sec; measured: 17,252 events/sec).
- **Detection Engine Evaluation**: Processes 5,000 events across active rules (target: >= 5,000 events/sec; measured: 631,241 events/sec).
- **Alert Correlation Upsert Latency**: Executes 200 alert upserts (target: < 50 ms/upsert; measured: 0.58 ms/upsert).
- **Dashboard Query Latencies**: Measures summary and paginated query response times (measured: < 7 ms).
- **Retention Purge Latency**: Purges 4,800 events while preserving alert evidence (measured: 64.66 ms).

---

### 2.3 Database & Storage Integration Tests (`tests/storage_integration.rs`)

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

### 2.4 End-to-End Pipeline Integration Tests (`tests/detection_pipeline.rs`)

Tests the complete operational lifecycle:
1. Instantiates temporary file-backed SQLite database.
2. Generates telemetry using `MockCollector` configured with `MockScenario::PortSweep`.
3. Normalizes raw TCP records into `NetworkEvent` objects.
4. Persists the batch transactionally via `EventRepository`.
5. Processes events through `DetectionEngine` with stateful `PortScanRule` (`NET-001`) and `ConnectionBurstRule` (`NET-002`).
6. Correlates and persists alerts via `AlertRepository::upsert_correlated_alert`.
7. Closes and reopens the database on an independent connection, verifying all alerts and evidence links survived.

---

### 2.5 Detection Unit & Stateful Rolling-Window Tests

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

### 2.6 Property-Based Tests (`proptest`)

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

### 2.7 Frontend Verification Suites (`ui/`)

- **Type Checking (`npm run typecheck`)**: Compiles TypeScript files with `tsc --noEmit` to ensure strict typing across all React components, page models, and Tauri IPC interfaces.
- **Static Analysis & Linting (`npm run lint`)**: Executes Oxlint across 29 files (116 rules), verifying 0 errors and 0 warnings.
- **Unit & Integration Tests (`npm test`)**: Executes Vitest test suite (`ui/src/test/app.test.tsx`), verifying navigation, dashboard metrics rendering, alert table displays, and settings updates.

---

## 3. Verification Execution Commands

### Run Full Rust Test Suite (Workspace-wide, 70 tests)
```powershell
cargo test --workspace
```

### Run Failure Injection Integration Suite
```powershell
cargo test --test failure_injection
```

### Run Performance Benchmark Suite
```powershell
cargo test --test benchmark_measurements -- --nocapture
```

### Run Code Formatting and Clippy Lints
```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Run Frontend Quality Checks
```powershell
cd ui
npm run typecheck
npm run lint
npm test
npm audit
```
