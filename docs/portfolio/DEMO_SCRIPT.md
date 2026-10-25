# SentinelX Live Demonstration Script & Technical Presentation

This script outlines a structured 3–5 minute demonstration of SentinelX tailored for engineering hiring managers, technical interviewers, and cybersecurity peers.

---

## 1. Demonstration Outline (3–5 Minute Walkthrough)

| Time | Segment | Screen / View | Action & Speaking Points |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:45** | **Architecture & Hook** | **Overview Dashboard** | Launch SentinelX. Highlight that this is a local-first, zero-cloud defensive monitoring desktop application built with Rust 2024 and Tauri 2. Explain how it inspects native Windows TCP table state without kernel drivers or administrative elevation. |
| **0:45 - 1:30** | **Telemetry Ingestion** | **Network Events** | Navigate to Network Events. Show live connection stream. Explain normalizer: decoding big-endian network byte order ports, translating socket states, filtering localhost loopbacks and listeners. |
| **1:30 - 2:30** | **Threat Detection** | **Security Alerts** | Demonstrate how the in-memory sliding window operates. Show `NET-001` (Port Scan) or `NET-002` (Connection Burst) alert triggered by 10+ distinct ports targeted in 60s. Click into Alert Details to reveal correlated evidence events. |
| **2:30 - 3:30** | **Triage & Persistence** | **Alert Details & Audit** | Click **Acknowledge Alert**, then **Resolve Alert** with operational notes. Navigate to **Audit History** to show the immutable audit entry recording the action. Close the app and reopen to prove zero data loss. |
| **3:30 - 4:30** | **Engineering & Trade-offs**| **Settings & About** | Show the About section. Discuss trade-offs: Why snapshot-based polling was chosen over packet capture, how SQLite WAL mode ensures lock-free concurrent reads, and how evidence-preserving retention prevents data corruption. |

---

## 2. Step-by-Step Execution Guide

### Step 1: Launch in Clean State
Launch SentinelX:
```powershell
& "$env:LOCALAPPDATA\Programs\SentinelX\sentinel-app.exe"
```
*Speaking Point:* *"SentinelX starts instantly with a sub-100ms cold boot time. Notice the health banner confirming active connection to our local embedded SQLite database running in WAL mode."*

### Step 2: Showcase Event Normalization
Navigate to **Network Events**:
- Point out the stream of active TCP sockets.
*Speaking Point:* *"Every entry is normalized from raw Windows IP Helper structures. We extract local and remote endpoints, translate network byte orders, and attach the owning Process ID (PID) to bridge network activity to host processes."*

### Step 3: Trigger a Controlled Detection
To demonstrate detection deterministically:
1. Navigate to **Telemetry**.
2. Toggle to **Demonstration Mock Mode** (or lower Rule `NET-001` threshold to 5 ports in **Detection Rules**).
3. Within seconds, a toast notification appears: *"Security Alert Detected: NET-001 Port-Scan-Like Activity"*.
*Speaking Point:* *"Our detection engine evaluates in-memory sliding windows with O(1) timestamp lookups. Because this source IP targeted more than 10 distinct destination ports inside 60 seconds, it triggered NET-001."*

### Step 4: Evidence Inspection & Incident Triage
1. Click **Security Alerts** in the sidebar.
2. Select the new `NET-001` alert.
3. Show the **Evidence Table**:
*Speaking Point:* *"Notice the evidence events attached to this alert. Even when automated 30-day retention cleanup runs, SentinelX protects any event referenced in the alert_evidence table, guaranteeing forensics integrity."*
4. Click **Acknowledge Alert**, then click **Resolve Alert** with note: *"Verified benign internal security audit"*.

### Step 5: Auditability & Persistence Verification
1. Navigate to **Audit History**:
*Speaking Point:* *"Every status change is committed inside an atomic transaction to an append-only audit log table, satisfying SOC 2 / compliance non-repudiation requirements."*
2. Close the application.
3. Relaunch SentinelX:
*Speaking Point:* *"Upon restart, SentinelX reconnects to the database, executes schema migrations if any version increment occurred, and restores our resolved alert and audit history intact."*

---

## 3. Anticipated Questions & Strong Technical Answers

### Q: "Why use periodic TCP table snapshots instead of raw packet capture (WinPcap / Npcap)?"
> **Answer:** *"Packet capture requires third-party kernel filter drivers (like Npcap), elevated administrative rights, and introduces significant memory and CPU overhead inspecting multi-gigabit payloads. For defensive situational awareness and detecting connection sweeps or burst anomalies, periodic TCP snapshots via `GetExtendedTcpTable` provide rich L4 metadata and process attribution (PIDs) with zero kernel drivers, standard user privileges, and negligible host overhead (<0.5% CPU)."*

### Q: "What are the limitations of this snapshot approach?"
> **Answer:** *"The key limitation is time resolution. Because we sample every 1,000 milliseconds, ephemeral connections that complete an entire TCP three-way handshake, payload exchange, and teardown in under 10 milliseconds between polling intervals will not appear in the snapshot. For comprehensive deep packet inspection or payload analysis, an enterprise agent with ETW or a kernel driver is necessary. SentinelX is designed as a lightweight, safe host monitor."*

### Q: "How does the desktop UI achieve real-time responsiveness without freezing?"
> **Answer:** *"We use Tauri 2 with asynchronous Rust IPC. All polling, snapshot normalization, detection aggregation, and SQLite persistence occur on background Tokio threads. Database writes operate in SQLite WAL (Write-Ahead Logging) mode so background batch inserts never block UI queries. When alerts trigger, Rust emits lightweight asynchronous IPC events to React, updating the UI with zero DOM freezes."*
