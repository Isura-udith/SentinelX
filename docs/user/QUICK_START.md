# SentinelX Quick Start Guide

Get up and running with SentinelX defensive network monitoring in less than 3 minutes.

---

## 1. Quick Installation

1. Download `SentinelX_1.0.0_x64-setup.exe` from the latest release.
2. Run the installer. On Windows SmartScreen, click **More info** > **Run anyway**.
3. Launch **SentinelX** from your Start Menu or Desktop.

---

## 2. Navigating the Dashboard

When SentinelX opens, you are greeted with the **Overview Dashboard**:

- **System Health:** Displays telemetry status (`LIVE WINDOWS TCP` or `DEMO MOCK`), database connection state, and uptime.
- **KPI Metrics:** Total events ingested, active alerts, high/critical detections, and distinct remote endpoints observed.
- **Activity Chart:** Real-time time-series timeline showing network event volume and threat alert triggers.
- **Recent Alerts:** Quick-action table showing unresolved security alerts.

---

## 3. Investigating an Alert

1. Navigate to **Security Alerts** in the left sidebar.
2. Locate an alert (e.g., `NET-001: Port-Scan-Like Activity Detection`).
3. Click the alert row to open the **Alert Details View**.
4. Review:
   - **Trigger Source:** The offending IP address.
   - **Severity Tier:** Low, Medium, High, or Critical.
   - **Evidence Events:** The exact sequence of TCP connections that breached the threshold.
   - **Audit Trail:** Historical actions taken on this alert.
5. Click **Acknowledge Alert** to signal investigation in progress, or **Resolve Alert** with operational notes to conclude the incident.

---

## 4. Toggling Live vs. Demo Mode

- **Live Mode:** Collects real Windows 11 TCP connection snapshots using the native Windows IP Helper API.
- **Demo / Mock Mode:** Runs a deterministic, safe in-memory scenario (ideal for software engineering demonstrations, presentations, and testing).
  - Open **Telemetry** in the sidebar.
  - Or in **Settings**, toggle **Demonstration Mode** and click **Save Configuration**.

---

## 5. Exiting SentinelX

- Closing the desktop window signals a graceful shutdown to background Tokio polling loops, flushes database write-ahead logs, and closes SQLite connections cleanly.
