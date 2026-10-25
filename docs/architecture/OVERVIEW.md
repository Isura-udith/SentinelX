# SentinelX System Architecture Overview

SentinelX is a local-first, defensive cybersecurity monitoring desktop application built specifically for Windows 11. It continuously inspects host network state via read-only Windows IP Helper APIs, normalizes raw telemetry into structured events, detects suspicious connection patterns (such as port sweeps and connection bursts) via stateful in-memory sliding windows, and provides persistent storage and a desktop SOC dashboard.

---

## 1. High-Level Architecture Diagram

```mermaid
graph TD
    subgraph Host ["Windows 11 Operating System"]
        WinAPI["Windows IP Helper API (GetExtendedTcpTable)"]
    end

    subgraph RustCore ["SentinelX Native Engine (Rust 2024)"]
        Collector["sentinel-collector<br/>• Raw TCP Snapshot Collection<br/>• Normalization & Byte-Order Decoding"]
        Engine["sentinel-detection<br/>• Sliding-Window Aggregator<br/>• Rule Evaluator (NET-001, NET-002)<br/>• Alert Deduplication & Cooldown"]
        Storage["sentinel-storage<br/>• SQLite Connection Pool (WAL Mode)<br/>• Compile-Time Migrations (0001–0003)<br/>• Audit Log & Retention Manager"]
        AppService["sentinel-app<br/>• Pipeline Coordinator<br/>• Background Polling Task (Tokio)<br/>• Event Emitter & State Manager"]
    end

    subgraph DesktopUI ["Tauri 2 Desktop Application (Chromium / WebView2)"]
        TauriIPC["Tauri IPC Command / Event Bridge"]
        ReactUI["React 19 Dashboard<br/>• Overview SOC KPIs & Charts<br/>• Network Events & Alert Tables<br/>• Detection Rules & Settings Config"]
    end

    subgraph LocalDisk ["Local User Filesystem (%LOCALAPPDATA%\\SentinelX)"]
        DBFile["sentinelx.db<br/>(SQLite Database with WAL)"]
        ConfigFile["settings.json<br/>(Persistent Preferences)"]
    end

    WinAPI -->|Read-Only FFI| Collector
    Collector -->|Normalized NetworkEvents| Engine
    Collector -->|Batch Persistence| Storage
    Engine -->|Triggered Alerts & Evidence| Storage
    Storage <-->|Read / Write Transactions| DBFile
    AppService -->|Coordinates| Collector
    AppService -->|Coordinates| Engine
    AppService -->|Coordinates| Storage
    AppService <-->|Strongly-Typed IPC| TauriIPC
    TauriIPC <-->|Async Commands & Events| ReactUI
    AppService <-->|Read / Write Settings| ConfigFile
```

---

## 2. Workspace Crate Architecture

The codebase is organized as a Cargo workspace with strict layer boundaries:

| Crate | Responsibility | Core Dependencies | Unsafe Policy |
| :--- | :--- | :--- | :--- |
| **`sentinel-core`** | Canonical domain types: `NetworkEvent`, `SecurityAlert`, `DetectionConfig`, `AlertSeverity`, strongly-typed UUID identifiers. | `serde`, `chrono`, `uuid`, `thiserror` | `#![deny(unsafe_code)]` |
| **`sentinel-collector`** | Native Windows telemetry collection via `GetExtendedTcpTable`, big-endian port decoding, socket normalization, and deterministic mock collector. | `sentinel-core`, `windows-sys` | Isolated `unsafe` FFI in `windows_tcp.rs` |
| **`sentinel-detection`** | Rule evaluation, in-memory sliding windows, alert cooldown suppression, and threshold scaling for NET-001 (Port Scan) and NET-002 (Burst). | `sentinel-core` | `#![deny(unsafe_code)]` |
| **`sentinel-storage`** | Local SQLite persistence, compile-time embedded migrations, transactional batch insertions, audit logging, and evidence-preserving retention. | `sentinel-core`, `sqlx` (WAL, sqlite) | `#![deny(unsafe_code)]` |
| **`sentinel-app`** | Tauri 2 desktop lifecycle, asynchronous command handlers, background Tokio scheduler, and event streaming. | All crates, `tauri`, `tokio`, `tracing` | `#![deny(unsafe_code)]` |
| **`ui`** | Single-page SOC desktop dashboard built with React 19, TypeScript, Tailwind CSS, Lucide icons, and Recharts. | React 19, `@tauri-apps/api`, Vite, Vitest | Managed by TypeScript & Oxlint |

---

## 3. Trust Boundaries & Security Model

```mermaid
graph LR
    subgraph UntrustedZone ["Untrusted / External Environment"]
        NetPackets["Network Traffic (Remote Hosts)"]
    end

    subgraph WindowsOS ["Windows Kernel / Subsystem"]
        TCPTable["Kernel TCP State Table"]
    end

    subgraph UserSpace ["User Execution Context (Medium Integrity)"]
        NativeRust["SentinelX Native Rust Engine<br/>• Parameterized Queries<br/>• Memory Safe<br/>• Read-Only Telemetry"]
        LocalData["Local Filesystem (%LOCALAPPDATA%\\SentinelX)<br/>• sentinelx.db (Per-User Restricted)"]
    end

    subgraph RendererSandbox ["Webview Sandbox (Tauri 2)"]
        Frontend["React UI Renderer<br/>• Strict CSP (script-src 'self')<br/>• No FS/Shell Access<br/>• Bound IPC Interface"]
    end

    NetPackets -.->|Establishes Sockets| TCPTable
    TCPTable -->|GetExtendedTcpTable FFI| NativeRust
    NativeRust <-->|SQLite Transactions| LocalData
    NativeRust <==|Type-Checked IPC Commands| Frontend
```

### Trust Boundary Rules
1. **Frontend Isolation:** The React webview is strictly unprivileged. It cannot read the filesystem, spawn operating system processes, or communicate directly over the network. It communicates with Rust exclusively via typed Tauri IPC invocations.
2. **Standard User Privilege:** SentinelX does not require administrative elevation or kernel-level drivers. It queries only the connection state visible to a standard user session.
3. **Local-First Boundary:** Telemetry and alert data never cross external network boundaries. All persistence is strictly local to `%LOCALAPPDATA%\SentinelX`.
