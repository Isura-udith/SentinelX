# SentinelX Technical Interview Preparation & Deep Dive Guide

This guide prepares the engineer to speak authoritatively on systems architecture, Windows operating system internals, Rust memory safety, detection algorithms, and desktop application engineering during technical interviews.

---

## 1. System Architecture & Language Selection

### Q1: "Why did you choose Rust for SentinelX?"
**Model Answer:**
> *"Rust was chosen for three key engineering reasons: memory safety without a garbage collector, zero-cost abstractions for Windows FFI, and strong concurrency guarantees. SentinelX runs continuous background telemetry polling loops and sliding-window aggregations. A language with a garbage collector (like Go, Java, or C#) introduces unpredictable pause times and higher memory baselines. In C++, FFI is easy, but manual memory management and data race risks in multi-threaded asynchronous code create security vulnerabilities. Rust's ownership model and the Tokio runtime allow us to achieve predictable sub-2ms collection cycles with a tiny 48 MB RAM footprint and zero risk of data races or use-after-free bugs."*

### Q2: "How is the Rust workspace structured and why?"
**Model Answer:**
> *"We organized the codebase into five distinct crates: `sentinel-core` (canonical domain models), `sentinel-collector` (Windows API telemetry collection), `sentinel-detection` (detection engine and rules), `sentinel-storage` (SQLite persistence and migrations), and `sentinel-app` (Tauri desktop coordination). This enforces strict architectural boundaries: domain entities have no dependencies on SQLite or Windows APIs, and the detection logic is completely decoupled from the collector. This separation allowed us to write property-based tests for detection rules and test the entire persistence layer using in-memory databases without needing a live Windows host."*

---

## 2. Windows Networking & Telemetry Internals

### Q3: "How does Windows TCP snapshot collection work under the hood?"
**Model Answer:**
> *"We interface with the Windows IP Helper library (`iphlpapi.dll`) via the `GetExtendedTcpTable` Win32 API from `windows-sys`. Because the number of active sockets on Windows can change dynamically, we implement a two-pass buffer query pattern: first calling the API with a null buffer to retrieve the required size, allocating a contiguous vector, and calling the API again. We wrap this in a bounded retry loop (up to 5 attempts) to gracefully handle concurrent socket creation. We query both IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) with `TCP_TABLE_OWNER_PID_ALL`, which returns socket states, endpoints, and the owning Process ID (PID)."*

### Q4: "Why are TCP snapshots not equivalent to packet capture, and what is the trade-off?"
**Model Answer:**
> *"Packet capture (using tools like WinPcap or Npcap) taps into the NDIS network driver layer, inspecting every individual ethernet frame and IP packet payload. This requires elevated Administrator privileges, third-party kernel drivers, and significant CPU/RAM overhead under multi-gigabit throughput. In contrast, `GetExtendedTcpTable` inspects the kernel's transport-layer socket table directly in user space without third-party drivers or elevation. The trade-off is time resolution: while packet capture sees every transient packet, snapshot polling samples the table at discrete intervals (e.g., 1,000ms), meaning ultra-fast ephemeral connections (<10ms) that close between cycles could be missed. For SentinelX's scope—detecting host port scanning and connection volume surges—TCP snapshots provide the ideal balance of safety, standard user privileges, low resource footprint, and process attribution."*

### Q5: "What challenges did you face with network byte order?"
**Model Answer:**
> *"Windows IP Helper structures store IPv4 addresses and port numbers in network byte order (Big-Endian). On x86_64 Windows architectures, the CPU is Little-Endian. A raw port value like `80` (HTTP) appears in memory as `0x5000` (20480 in decimal) if interpreted naively. We implemented strict byte-order decoding using `u16::from_be` for ports and `Ipv4Addr::from(u32::from_be(raw_ip))` for addresses, and validated this with property-based roundtrip tests in `sentinel-collector`."*

---

## 3. Detection Algorithms & Rule Engineering

### Q6: "How does the detection engine track sliding windows without memory leaks?"
**Model Answer:**
> *"The detection engine maintains in-memory rolling time windows keyed by source IP address. Each incoming event timestamp is compared against the window duration (e.g., 60 seconds). During evaluation, events older than `current_time - window_duration` are pruned from the state. Furthermore, we enforce hard bounding: evidence event IDs per alert are capped at 20, and alert suppression cooldowns (300 seconds) prevent identical alerts from re-triggering and consuming memory during sustained scans. In unit tests, we validated that out-of-order timestamps and future clock skew are handled safely without arithmetic overflow."*

### Q7: "How do you test your detection rules?"
**Model Answer:**
> *"We use a three-tier testing pyramid: First, standard unit tests with synthetic event sequences covering expected hits, non-matching traffic, out-of-order events, and cooldown expiration. Second, property-based tests using `proptest` generating randomized permutations of IPs and ports to verify that duplicate ports never inflate distinct port counts and that independent source IPs never cross-contaminate. Third, end-to-end pipeline tests in `detection_pipeline.rs` feeding live mock collectors through the full persistence and detection flow."*

---

## 4. Storage, Concurrency & Database Migrations

### Q8: "How does SentinelX handle SQLite concurrency in a desktop app?"
**Model Answer:**
> *"SQLite by default can suffer from lock contention (`SQLITE_BUSY`) when background threads write while the GUI reads. We solve this by enforcing Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and normal synchronous mode (`PRAGMA synchronous = NORMAL`). In WAL mode, SQLite allows concurrent readers to query the database simultaneously while a background writer thread commits batch inserts. We also configure a 5,000ms busy timeout on the connection pool."*

### Q9: "How do database migrations work without shipping external SQL files?"
**Model Answer:**
> *"We use SQLx compile-time migrations via `sqlx::migrate!('./migrations')`. During `cargo build`, the SQL migration files (`0001_initial_schema.sql`, `0002_detection_indexes.sql`, `0003_rule_config.sql`) are validated and embedded directly into the compiled executable as static byte arrays. When SentinelX starts up, it connects to SQLite and executes any pending migrations inside an atomic transaction. This guarantees zero missing-file errors when distributing the single `.exe` installer."*

### Q10: "How does your data retention policy preserve forensic evidence?"
**Model Answer:**
> *"Many systems naively delete all events older than 30 days, which destroys the evidence needed to investigate older alerts. In SentinelX, our `RetentionManager` uses a selective subquery: `DELETE FROM network_events WHERE timestamp < ? AND id NOT IN (SELECT event_id FROM alert_evidence)`. This ensures that routine background events expire gracefully while any event that contributed to a security alert is permanently preserved until the alert itself is purged."*

---

## 5. Desktop Security & Packaging (Tauri 2)

### Q11: "How is the Tauri desktop application secured against web vulnerabilities?"
**Model Answer:**
> *"We adhere to the principle of least privilege across both the frontend and native layers. First, the Tauri capabilities file (`capabilities/default.json`) permits only `core:default`. Capabilities like arbitrary filesystem reading, shell execution, or external URL loading are disabled. Second, we configure a strict Content Security Policy (`script-src 'self'; connect-src 'self'`) blocking inline or remote scripts. Third, all IPC command arguments sent from React to Rust are strongly typed and validated against bounds limits before database execution."*

### Q12: "What was the most difficult engineering challenge and how did you solve it?"
**Model Answer:**
> *"The most challenging problem was ensuring zero UI thread blocking during high-volume telemetry surges while maintaining consistent alert ordering. Initially, telemetry collection, persistence, and detection were competing for locks. We solved this by implementing the `PipelineCoordinator` architecture: decoupling collection into a dedicated background Tokio task, batching database inserts into single transactions, and using asynchronous Tauri event emitters (`app_handle.emit`) to dispatch state updates to the React UI without blocking on UI confirmation."*

### Q13: "What would you improve in v2.0?"
**Model Answer:**
> *"In future versions, I would add:
> 1. **ETW (Event Tracing for Windows) Integration:** Complementing periodic TCP snapshots with the `Microsoft-Windows-Kernel-Network` ETW provider to capture transient (<10ms) connections.
> 2. **Process Binary Attribution:** Resolving owning PIDs to full executable file paths and cryptographic hashes via `CreateToolhelp32Snapshot` and `QueryFullProcessImageName`.
> 3. **Commercial Code Signing:** Implementing automated CI signing via Azure Trusted Signing or DigiCert EV to eliminate Windows SmartScreen warnings on first run."*
