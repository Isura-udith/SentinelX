# SentinelX Mock Data Audit & Real-Data Verification Report

**Document Version:** 1.0.0  
**Target Architecture:** Windows 11 x64, Rust 2024 (1.85+), Tauri 2.0, React 19  
**Audit Date:** 2026-10-26  
**Auditor:** Senior Systems & Release Engineer  

---

## 1. Executive Summary

This audit catalogs all instances of mock, simulated, placeholder, and hardcoded data across the **SentinelX** repository. The objective is to ensure that production application paths execute against live operating system telemetry (Windows IP Helper API `GetExtendedTcpTable`) and persistent SQLite storage (`sqlx` WAL mode), while separating legitimate automated test fixtures into dedicated test suites.

---

## 2. Comprehensive Inventory of Findings

### Finding 1: In-Browser Mock Provider in Production Command Service
- **File / Component:** `ui/src/services/tauriCommands.ts` (`callBackend`, `getMockResponse`)
- **Lines:** 44–46, 109–397 (~290 lines)
- **Description:** A monolithic `getMockResponse<T>` function returned fabricated data for all 17 Tauri commands whenever `isTauriEnvironment()` evaluated to false. Values included:
  - Fabricated KPI numbers: `total_events: 1240`, `events_last_hour: 410`, `open_alerts: 3`, `successful_collections: 58`
  - Randomized time series: `Math.floor(Math.random() * 80) + 20`
  - Fabricated alert entries: `alt-001`, `NET-001:192.168.1.105`
  - Fabricated network events: `evt-001`, `192.168.1.105:49152 -> 192.168.1.1:80`
  - Hardcoded non-existent paths: `C:\Users\Mock\AppData\Local\SentinelX\sentinelx.db`
  - Stale version number: `0.2.0` (production is `1.0.0`)
- **Affects Production Build?** YES (Risk). If loaded outside the Tauri desktop webview or if webview IPC handshake was delayed, the application silently served fabricated data instead of indicating backend unavailability.
- **Acceptable as Test Fixture?** NO inside `tauriCommands.ts`. Acceptable only when isolated in `ui/src/test/`.
- **Replacement Strategy:**
  1. Extract test fixtures into `ui/src/test/testFixtures.ts`.
  2. In `tauriCommands.ts`, delete `getMockResponse` entirely.
  3. If `!isTauriEnvironment()`, `callBackend` now throws an explicit error: `"Tauri backend IPC unavailable: Cannot invoke '{command}'. SentinelX requires the Windows desktop Tauri runtime."`
  4. In `ui/src/test/setup.ts`, mock `@tauri-apps/api/core` `invoke` to consume `testFixtures.ts` for Vitest unit/integration testing.
- **Verification Post-Replacement:**
  - Production bundle `dist/assets/*.js` contains 0 references to `C:\Users\Mock` or `Math.random()`.
  - Vitest test suite (`npm test`) passes all 7 integration tests in <2 seconds.

---

### Finding 2: `Math.random()` in Toast Notification Key Generator
- **File / Component:** `ui/src/App.tsx` (`addToast`)
- **Line:** 31
- **Description:** Toast notification IDs were computed via ``${Date.now()}-${Math.random()}``.
- **Affects Production Build?** YES. Unnecessary use of pseudo-randomness in UI state.
- **Acceptable as Test Fixture?** No, unnecessary.
- **Replacement Strategy:** Use standard `crypto.randomUUID()` or sequential monotonic IDs.
- **Verification Post-Replacement:** Verified with `grep` that `Math.random` is completely absent from all production source files.

---

### Finding 3: Mismatched Telemetry Source Dropdown Values in Network Events
- **File / Component:** `ui/src/pages/EventsPage.tsx`
- **Lines:** 204–207
- **Description:** Dropdown filter offered `<option value="Mock">Mock</option>` and `<option value="WindowsTcp">WindowsTcp</option>`. In the Rust backend (`crates/sentinel-app/src/commands.rs`), the filter parser checked for `"synthetic"` or `"windows_tcp"`. Selecting either `"WindowsTcp"` or `"Mock"` resulted in backend rejection: `AppError::Validation("Invalid telemetry source: ...")`.
- **Affects Production Build?** YES. Breaking bug preventing user from filtering by source in production UI.
- **Acceptable as Test Fixture?** N/A (UI bug).
- **Replacement Strategy:**
  1. Standardize UI options to `<option value="windows_tcp">Windows TCP Snapshot</option>` and `<option value="synthetic_simulator">Synthetic Test Telemetry</option>`.
  2. Update backend `commands.rs` to accept `"mock"`, `"synthetic"`, `"windows_tcp"`, and `"windowstcp"` case-insensitively.
- **Verification Post-Replacement:** Verified query execution and filtering against live SQLite database.

---

### Finding 4: Mock Collector Instance Used as Thread-Swap Placeholder in Production Pipeline
- **File / Component:** `crates/sentinel-app/src/pipeline.rs` (line 198) and `crates/sentinel-app/src/telemetry.rs` (line 153)
- **Description:** When dispatching the blocking native Windows IP Helper call to `tokio::task::spawn_blocking`, the coordinator used:
  `let mut collector = std::mem::replace(&mut self.collector, Box::new(MockCollector::new()));`
  If `spawn_blocking` panicked or terminated unexpectedly before restoring the collector, the pipeline would be permanently stuck with a `MockCollector`.
- **Affects Production Build?** YES. Latent reliability defect that could silently swap live telemetry with mock telemetry upon thread failure.
- **Acceptable as Test Fixture?** NO for production thread swapping.
- **Replacement Strategy:** Introduce `StandbyCollector` in `sentinel-collector` which implements `TelemetryCollector` but returns `Err(CollectorError::Uninitialized(...))`, guaranteeing that no synthetic data is ever produced by the placeholder.
- **Verification Post-Replacement:** Verified with Rust tests and clippy.

---

### Finding 5: Type Discrepancy Between Rust `AuditEntryDto.id` and TypeScript `AuditEntry.id`
- **File / Component:** `ui/src/types/index.ts` vs `crates/sentinel-app/src/commands.rs`
- **Description:** `AuditEntryDto.id` in Rust serialized a UUID string (`pub id: String`), while `AuditEntry` in TypeScript typed `id: number`.
- **Affects Production Build?** YES. React keys and audit table displays could experience unexpected type behavior.
- **Acceptable as Test Fixture?** N/A (Type definition defect).
- **Replacement Strategy:** Update TypeScript `AuditEntry.id` to `string | number;`.
- **Verification Post-Replacement:** `npm run typecheck` passes with zero errors.

---

### Finding 6: Unhandled Core Backend Connection Errors in Root Application View
- **File / Component:** `ui/src/App.tsx` and `ui/src/components/layout/Header.tsx`
- **Description:** If `getSystemStatus()` or `getDashboardSummary()` threw a network or Tauri error, the failure was only logged to `console.error`. The UI rendered a generic unavailable text without error details or a retry action.
- **Affects Production Build?** YES. Degrades error visibility when backend services fail.
- **Acceptable as Test Fixture?** N/A.
- **Replacement Strategy:** Add explicit `backendError` state in `App.tsx` with error banner display and a "Retry Connection" button.
- **Verification Post-Replacement:** Verified error state handling in UI.

---

## 3. Retained Test Fixtures (Documented Separation)

The following test components contain synthetic data and are **intentionally retained** exclusively for automated validation and verification:

1. **`crates/sentinel-collector/src/mock.rs` (`MockCollector`, `MockScenario`):**
   - **Purpose:** Used in `tests/mock_integration.rs`, `tests/detection_pipeline.rs`, and property tests to verify detection logic (port scan and connection burst algorithms) deterministically against known test vectors without requiring OS network packets.
   - **Provenance:** Every event generated by `MockCollector` is explicitly tagged with `telemetry_source = TelemetrySource::SyntheticSimulator`.
   - **Production Isolation:** In release builds on Windows, `use_mock` is `false` by default. If `--mock` is explicitly passed via CLI or activated via Settings, the UI displays a prominent amber badge: `DEMO / MOCK MODE`.

2. **`ui/src/test/testFixtures.ts`:**
   - **Purpose:** Supplies deterministic mock responses to Vitest during frontend unit and component integration tests.
   - **Production Isolation:** Excluded from the Vite production bundle (`ui/dist/`).

---

## 4. Verification Matrix

| Finding ID | Production File | Issue | Status | Verification Method |
|---|---|---|---|---|
| F-01 | `ui/src/services/tauriCommands.ts` | 290 lines of mock fallback data in production code | FIXED | Extracted to test fixtures; runtime throws explicit IPC error |
| F-02 | `ui/src/App.tsx` | `Math.random()` in toast ID generation | FIXED | Replaced with `crypto.randomUUID()` |
| F-03 | `ui/src/pages/EventsPage.tsx` | Invalid source dropdown values ("Mock", "WindowsTcp") | FIXED | Updated UI values and Rust parser to support aliases |
| F-04 | `crates/sentinel-app/src/pipeline.rs` | `MockCollector` used as thread swap placeholder | FIXED | Replaced with `StandbyCollector` |
| F-05 | `ui/src/types/index.ts` | `AuditEntry.id` type mismatch (`number` vs `String`) | FIXED | Updated TypeScript definition |
| F-06 | `ui/src/App.tsx` | Silent backend connection errors | FIXED | Added visible error alert banner and Retry action |
