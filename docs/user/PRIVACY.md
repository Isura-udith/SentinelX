# SentinelX Privacy & Data Protection Policy

SentinelX is committed to total user privacy and defensive transparency. This document details what data the application collects, where it is stored, and what data is intentionally excluded.

---

## 1. Zero Cloud Transmission Guarantee

SentinelX operates under a **strict local-first, zero-cloud architecture**:
- **No Remote Telemetry:** SentinelX does not send diagnostic telemetry, error reports, or usage analytics to any cloud server, third party, or external database.
- **No Cloud Dependencies:** The application functions fully offline without internet connectivity.
- **Air-Gapped Friendly:** SentinelX can operate inside isolated, air-gapped security laboratory environments.

---

## 2. Telemetry Scope: What We Collect

SentinelX periodically samples the native Windows TCP state table using read-only Windows IP Helper APIs (`GetExtendedTcpTable`):

| Data Attribute | Example Value | Purpose |
| :--- | :--- | :--- |
| **Local IP Address** | `192.168.1.100` | Identifies host interface initiating or receiving the socket. |
| **Local Port** | `54321` | Identifies ephemeral source port. |
| **Remote IP Address** | `203.0.113.50` | Identifies destination host for threat correlation. |
| **Remote Port** | `443` | Identifies transport service (e.g., HTTPS, SSH, SMB). |
| **Connection State** | `ESTABLISHED` | Identifies whether socket is active, negotiating, or closing. |
| **Process ID (PID)** | `4128` | Operating system Process ID of the application that owns the socket. |
| **Timestamp** | `2026-10-25T15:30:00Z` | Precise UTC time of observation for sliding-window analysis. |

---

## 3. What We Strictly Do NOT Collect

SentinelX is deliberately designed as a **metadata-only defensive monitor**. It does **NOT**:
- Sniff or inspect packet payloads.
- Intercept HTTP/HTTPS request headers, cookies, or POST bodies.
- Collect passwords, credentials, API keys, or private tokens.
- Inspect file contents, keystrokes, clipboard buffers, or browser histories.
- Log process memory, thread stacks, or screen captures.
- Intercept DNS queries or read user documents.

---

## 4. Local Storage & Operator Control

1. **Storage Location:**  
   All collected events and alerts are saved in a local SQLite file:
   ```text
   %LOCALAPPDATA%\SentinelX\sentinelx.db
   ```
   Access is restricted by Windows File System permissions to your local user account.

2. **Automated Event Expiration:**  
   By default, events older than 30 days are automatically purged from disk during shutdown or background maintenance cycles.

3. **Complete Data Eradication:**  
   You may permanently purge all monitoring history at any time by closing SentinelX and deleting the `%LOCALAPPDATA%\SentinelX` directory.
