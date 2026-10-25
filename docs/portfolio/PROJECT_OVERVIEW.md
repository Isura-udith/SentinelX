# SentinelX Project Overview & Engineering Case Study

**Project Name:** SentinelX  
**Role:** Lead Systems, Security, & Release Engineer  
**Core Technologies:** Rust 2024, Windows IP Helper FFI, SQLite (WAL Mode), SQLx, Tokio, Tauri 2, React 19, TypeScript, Tailwind CSS  
**Target Platform:** Windows 11 (x86_64)  
**Release Version:** v1.0.0 (Release Candidate)  

---

## 1. Project Background & Problem Statement

Modern Windows endpoints require continuous defense against unauthorized network reconnaissance, lateral movement, and anomalous connection volume surges. Traditional enterprise EDR tools (CrowdStrike, Defender for Endpoint) rely on proprietary cloud architectures and kernel-level drivers, introducing complexity, high resource overhead, and privacy concerns for security researchers and privacy-conscious users.

**The Engineering Challenge:** Build a high-performance, local-first Windows 11 defensive monitoring tool that:
1. Detects suspicious transport-layer activity (port scans and burst anomalies).
2. Runs without administrative elevation or third-party kernel drivers.
3. Operates entirely locally with zero cloud dependencies.
4. Delivers a responsive, modern desktop SOC experience with sub-millisecond query latency.

---

## 2. Key Architecture Decisions

### 2.1 Why Rust?
- **Deterministic Memory Safety:** Memory safety guarantees without garbage collection pauses, critical for background monitoring tasks that must maintain constant CPU/RAM envelopes.
- **Direct Windows API Interop:** Safe, low-overhead FFI bindings to native Windows IP Helper structures.
- **Strict Concurrency Guarantees:** Thread-safe state coordination across asynchronous Tokio runtimes and Tauri desktop IPC.

### 2.2 Why Tauri 2 over Electron?
- **Resource Footprint:** SentinelX compiles to a lean ~16 MB binary with a ~3.8 MB installer, consuming ~45 MB RAM at runtime, compared to typical Electron applications requiring 150+ MB installers and 300+ MB RAM.
- **Native OS Integration:** Native Windows WebView2 runtime utilization, elimination of bundled Chromium binaries, and native NSIS packaging.

### 2.3 Why SQLite in WAL Mode?
- **Zero Server Setup:** Embedded, zero-configuration local database requiring no daemon processes or network ports.
- **Lock-Free Concurrency:** Write-Ahead Logging (WAL) mode enables simultaneous reading from the GUI layer while the background collector commits batch writes without UI blocking.

---

## 3. Engineering Highlights

1. **Native IP Helper FFI with Safe Memory Bounds:**
   - Isolated `unsafe` FFI in `sentinel-collector` calling `GetExtendedTcpTable`.
   - Dynamic buffer resizing retry loop handling concurrent table expansion.
   - Complete Big-Endian to host byte order translation for IPv4, IPv6, and port numbers.
2. **Stateful In-Memory Sliding Window Detection:**
   - Sliding-window timestamp bucketing with O(1) deduplication.
   - Alert suppression cooldown mechanisms preventing notification fatigue.
   - Bounded evidence collections preventing memory exhaustion.
3. **Compile-Time Embedded Migrations:**
   - 100% of database schema migrations are embedded into the compiled binary via `sqlx::migrate!`. Fresh installs and upgrades execute migrations in atomic transactions with zero runtime filesystem dependencies.
4. **Evidence-Preserving Retention Engine:**
   - Automated aging mechanism cleans historical events past retention windows while strictly preserving any event referenced as evidence for an existing security alert.
5. **Rigorous Quality Assurance:**
   - 88+ automated tests including property-based tests (`proptest`), integration pipelines, failure injection tests, and frontend Vitest suites.
   - Automated release validation pipeline (`scripts/verify-release.ps1`).

---

## 4. Key Metrics & Benchmarks

| Metric | Target | Verified Performance |
| :--- | :--- | :--- |
| **Installer Size** | < 10 MB | **3.78 MB** (NSIS Compressed) |
| **Release Binary Size** | < 25 MB | **15.48 MB** (x86_64 release) |
| **Idle CPU Utilization**| < 1.0% | **< 0.3%** on Windows 11 host |
| **Idle Memory Footprint**| < 100 MB | **~48 MB RAM** |
| **Snapshot Ingestion Time**| < 15 ms | **~1.8 ms** per 50 connections |
| **Test Suite Pass Rate** | 100% | **88 / 88 Tests Passed** |
| **Known Vulnerabilities** | 0 | **0 Vulnerabilities** (`npm audit` clean) |
