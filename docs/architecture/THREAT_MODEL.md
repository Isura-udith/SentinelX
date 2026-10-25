# SentinelX Threat Model & Security Design

**System:** SentinelX Host Defensive Network Monitor (Windows 11)  
**Security Framework:** STRIDE Threat Classification  
**Target Audience:** Security Engineers, Desktop Application Engineers, and SOC Analysts  

---

## 1. System Assets & Security Objectives

| Asset | Description | Primary Security Objective |
| :--- | :--- | :--- |
| **Telemetry History** | Historical TCP connection snapshots and normalized events. | **Integrity & Availability:** Prevent unauthorized modification or deletion outside retention rules. |
| **Security Alerts** | Detections of suspicious activity with associated evidence IDs. | **Integrity:** Ensure alert provenance and evidence links are tamper-evident. |
| **Audit Log Trail** | Record of user actions (acknowledgment, resolution, config changes). | **Non-Repudiation:** Append-only persistence; records cannot be modified or hidden. |
| **Host System Stability**| CPU, RAM, and disk utilization of the monitored Windows 11 host. | **Availability:** Monitoring must not degrade host performance, cause memory leaks, or block host networking. |

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing (Identity & Origin)
- **Threat S-1:** A malicious process on the host generates fabricated telemetry events or alerts to mislead analysts.
  - *Mitigation:* Telemetry collection is performed strictly within native Rust via direct Windows API invocation (`GetExtendedTcpTable`). The frontend renderer cannot inject synthetic telemetry into live databases; mock mode is strictly separated and visually flagged in the UI.
- **Threat S-2:** A rogue script pretends to be the Tauri frontend to execute backend commands.
  - *Mitigation:* Tauri IPC handlers use typed internal message channels with strict origin restrictions. Outside web connections cannot invoke Tauri handlers.

### 2.2 Tampering (Data Modification)
- **Threat T-1:** An adversary alters historical network events in SQLite to conceal malicious traffic.
  - *Mitigation:* Database queries use parameterized statements (`sqlx`). The database file is placed in `%LOCALAPPDATA%\SentinelX` protected by standard Windows discretionary access control lists (DACLs) restricted to the logged-in user.
- **Threat T-2:** Modifying detection rules to disable alerting for specific IPs.
  - *Mitigation:* Rule updates are logged immediately to the immutable `audit_log` table with timestamps and parameter diffs.

### 2.3 Repudiation (Denial of Actions)
- **Threat R-1:** An operator acknowledges or resolves a high-severity alert and subsequently denies taking the action.
  - *Mitigation:* Every alert status transition requires an audit entry containing `actor`, `action`, `target_id`, and UTC timestamp recorded within the same database transaction.

### 2.4 Information Disclosure (Confidentiality Leaks)
- **Threat I-1:** Sensitive user passwords or private communications are exposed in logs or database files.
  - *Mitigation:* SentinelX explicitly collects only L4 transport metadata (IP addresses, port numbers, TCP flags, PIDs). Payload inspection is architecturally excluded. Diagnostic tracing logs filter internal targets and exclude memory dumps.
- **Threat I-2:** Webview loads external malicious scripts that exfiltrate event history.
  - *Mitigation:* Strict Content Security Policy (`script-src 'self'; connect-src 'self'`). Outbound network requests from the webview layer are prohibited.

### 2.5 Denial of Service (System Availability)
- **Threat D-1:** Rapid network traffic flooding exhausts host memory or disk space.
  - *Mitigation:*
    - In-memory detection sliding windows enforce strict bounding (`max_evidence_ids_per_alert = 20`, window size caps).
    - Database queries enforce pagination limits (max 200 rows per query).
    - Automated retention manager prunes non-evidence events older than 30 days.
    - Collector executes asynchronously with bounded Tokio thread pools.
- **Threat D-2:** Excessive SQLite file locking causing GUI freezes.
  - *Mitigation:* WAL mode (`PRAGMA journal_mode = WAL`) allows concurrent readers to query while the background scheduler commits writes without lock contention.

### 2.6 Elevation of Privilege
- **Threat E-1:** Attacker exploits SentinelX to achieve Administrator or SYSTEM privileges.
  - *Mitigation:* SentinelX runs strictly in medium integrity (unprivileged user context). It installs no kernel drivers, no Windows services, and requires no administrative elevation.

---

## 3. Scope & Operational Limitations

1. **Snapshot-Based Telemetry:**
   - SentinelX samples the Windows TCP table at discrete intervals (default: 1,000 ms).
   - High-speed ephemeral connections (e.g., fast scanning tools sending single SYN/RST packets or sockets opened and closed within <10ms) may not appear in table snapshots.
2. **Defensive Non-Interference:**
   - SentinelX is purely passive and defensive. It does not drop packets, block connections, or terminate offending processes.
   - It is designed for situational awareness, auditing, and defensive portfolio demonstration, not active enterprise containment.
