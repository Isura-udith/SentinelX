# SentinelX Portfolio Screenshot & Visual Asset Guide

This guide provides a standardized checklist and instructions for capturing high-impact, professional screenshots of SentinelX for technical portfolios, GitHub showcases, and engineering resumes.

---

## 1. Visual Capture Standards

To ensure visual consistency and portfolio quality:
- **Display Resolution:** Minimum 1920x1080 (1080p); recommended 2560x1440 (1440p) at 100% DPI scaling.
- **Theme:** Default Dark Mode (ensures cyber defense SOC visual appeal).
- **Window State:** Standard maximized desktop window (1366x868 minimum boundary).
- **Data State:** Use active telemetry or the built-in deterministic demo dataset to populate populated tables and charts. Avoid capturing empty states for portfolio hero images.

---

## 2. Key Showcase Screens & Capture Checklist

| # | View Name | File Target | Key Elements to Showcase |
| :- | :--- | :--- | :--- |
| **01** | **Overview SOC Dashboard** | `docs/portfolio/screenshots/01_overview_dashboard.png` | System health badge (`LIVE WINDOWS TCP`), 4 KPI summary cards, interactive time-series timeline chart, severity breakdown donut, and recent alerts table. |
| **02** | **Network Events Stream** | `docs/portfolio/screenshots/02_network_events.png` | Paginated event rows with Source IP/Port, Destination IP/Port, PID, Protocol (TCP), and Connection States (`ESTABLISHED`, `TIME_WAIT`). |
| **03** | **Security Alerts Feed** | `docs/portfolio/screenshots/03_security_alerts.png` | Alert cards highlighting `NET-001` (Port Scan) and `NET-002` (Burst), color-coded severity badges (`High`, `Medium`), and status pills (`New`, `Acknowledged`). |
| **04** | **Alert Deep Dive & Evidence** | `docs/portfolio/screenshots/04_alert_details_evidence.png` | Selected alert details showing timeline, trigger attributes, correlated evidence event list with port numbers, and associated audit trail. |
| **05** | **Detection Rule Tuning** | `docs/portfolio/screenshots/05_detection_rules.png` | Rule cards with threshold sliders, window duration fields, alert cooldown inputs, and active status toggles. |
| **06** | **Telemetry Diagnostics** | `docs/portfolio/screenshots/06_telemetry_controls.png` | Live collection start/stop controls, polling frequency metrics, raw record counters, and latency measurements. |
| **07** | **Settings & About Section** | `docs/portfolio/screenshots/07_settings_about.png` | Database paths, retention policies, and the About SentinelX card showcasing version `v1.0.0`, platform tags, and MIT license. |

---

## 3. Recommended Capture Workflow (Windows 11)

1. Launch SentinelX:
   ```powershell
   & "$env:LOCALAPPDATA\Programs\SentinelX\sentinel-app.exe"
   ```
2. Navigate to **Telemetry** and ensure live or demo collection is active to generate populated charts.
3. Use Windows Snipping Tool (`Win + Shift + S`) with **Window Snip** mode to capture pixel-perfect window borders without background desktop clutter.
4. Save images to `docs/portfolio/screenshots/` with descriptive filenames.
