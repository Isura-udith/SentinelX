# Performance Benchmarks & Resource Limits: SentinelX

## 1. Benchmark Methodology & Test Environment

To establish empirical performance baselines and verify that SentinelX operates efficiently within single-machine Windows 11 resource constraints, an automated synthetic workload benchmark suite was executed via [`tests/benchmark_measurements.rs`](file:///d:/SentinelX/tests/benchmark_measurements.rs).

### Environment Specification
- **Operating System**: Microsoft Windows 11 Pro (64-bit, build 10.0.26100)
- **Target Architecture**: `x86_64-pc-windows-msvc`
- **CPU**: Multi-core x86_64 Processor
- **Storage Subsystem**: NVMe Solid State Drive
- **Toolchain**: `rustc 1.99.1`, `cargo 1.99.1`, Node.js `v24.14.0`
- **Database Engine**: Embedded SQLite 3.x (via `sqlx`, WAL mode enabled)
- **Dataset Size**: 5,000 synthetic normalized TCP events, 200 alert correlation upserts, 11 retention cycles.

---

## 2. Empirical Benchmark Measurements

The following measurements were captured directly from the test execution:

```
=======================================================
SENTINELX PHASE 5 PERFORMANCE & RELIABILITY BENCHMARK
=======================================================

[-] Database initialization + SQLite migrations duration: 14.83 ms
[-] Event Ingestion Throughput: 5000 events inserted in 289.82 ms (17252 events/sec)
[-] Detection Engine Throughput: 5000 events evaluated in 7.92 ms (631241 events/sec, 20 alerts detected)
[-] Alert Correlation Upsert Latency: 200 upserts completed in 115.34 ms (average 0.58 ms/upsert)
[-] Dashboard Summary Query Latency: 6.94 ms (events: 5000, open alerts: 20)
[-] Paginated Events Query Latency (50 items): 1.57 ms (total: 5000)
[-] Paginated Alerts Query Latency (50 items): 3.49 ms (total: 20)
[-] Database File Size on Disk (after 5,000 events + 200 alerts): 2156.00 KB (2.11 MB)
[-] Retention Cycle Execution Latency: 64.66 ms (purged 4800 events, executed 11 batches)

=======================================================
BENCHMARK ACCEPTANCE TARGET VERIFICATION PASSED
=======================================================
```

---

## 3. Performance Acceptance Target Comparison

| Metric | Acceptance Target | Measured Baseline | Margin / Headroom | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Cold DB Startup & Migrations** | `< 250 ms` | **14.83 ms** | 16.8x faster | **PASSED** |
| **Event Ingestion Throughput** | `≥ 1,000 events/sec` | **17,252 events/sec** | 17.2x target | **PASSED** |
| **Detection Engine Throughput** | `≥ 5,000 events/sec` | **631,241 events/sec** | 126x target | **PASSED** |
| **Alert Correlation Upsert Latency** | `< 50.0 ms / upsert` | **0.58 ms / upsert** | 86.2x faster | **PASSED** |
| **Dashboard Summary Latency** | `< 500 ms` | **6.94 ms** | 72x faster | **PASSED** |
| **Paginated Events Query (50 items)** | `< 250 ms` | **1.57 ms** | 159x faster | **PASSED** |
| **Paginated Alerts Query (50 items)** | `< 250 ms` | **3.49 ms** | 71x faster | **PASSED** |
| **Retention Purge Latency (4.8k items)** | `< 2,000 ms` | **64.66 ms** | 30.9x faster | **PASSED** |
| **On-Disk DB Footprint (5.2k records)** | `< 25.0 MB` | **2.11 MB** | 11.8x headroom | **PASSED** |

---

## 4. Resource Bounding & Reliability Analysis

### 4.1 Bounded In-Memory Queue & Concurrency
- **Collection Serialization**: `PipelineCoordinator::is_running` atomic flag guarantees that concurrent or overlapping polling tasks never spawn. If a collection cycle is actively running, subsequent poll triggers are safely dropped with an operational log message.
- **Batch Clamping**: `DetectionEngine` enforces `max_batch_size = 100,000`. Batches exceeding this are rejected with `BatchSizeExceeded` before memory allocation.
- **Telemetry Record Clamping**: `sentinel-collector::windows_tcp` clamps table enumeration to `MAX_SNAPSHOT_RECORDS = 50,000` records per snapshot.
- **Evidence Reference Limits**: Individual security alerts cap attached evidence to `MAX_EVIDENCE_COUNT = 1,000` event IDs.

### 4.2 SQLite Durability & Concurrency Trade-Offs
- **Write-Ahead Logging (WAL)**: `PRAGMA journal_mode = WAL;` enables concurrent readers and writers without lock contention on read-heavy dashboard queries.
- **Busy Timeout**: `PRAGMA busy_timeout = 5000;` ensures transient write locks hold for up to 5 seconds before returning a lock error.
- **Foreign Keys**: `PRAGMA foreign_keys = ON;` enforces referential integrity on alert-event relationships.
- **Durability Trade-off**: Standard synchronous mode (`PRAGMA synchronous = NORMAL;`) was retained. This provides robust durability against application crashes while eliminating synchronous fsync bottlenecks on Windows SSD filesystems.

### 4.3 Retention & Disk Growth Management
- The retention engine executes in bounded transactional batches (default: 500 events per transaction batch).
- Strategy A retention performs an anti-join against `alert_events`, ensuring historical events that serve as forensic evidence for alerts are **never** deleted by log rotation.
- Disk usage scales predictably: ~2 MB per 5,000 events. With a default 7-day retention window on a standard desktop experiencing 100 connections/min, steady-state disk footprint remains bounded below 500 MB.

### 4.4 Frontend Responsiveness
- All dashboard tables (Events, Alerts, Audit Logs) implement server-side pagination with a default page size of 50 records and a hard upper clamp of 500 records.
- Query offsets are bounded to `<= 1,000,000` to prevent deep offset scan attacks on SQLite B-trees.
- React components use Promise chaining and unmount cleanup flags to eliminate redundant re-render cascades.
