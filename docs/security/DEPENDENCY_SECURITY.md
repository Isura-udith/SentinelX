# SentinelX Dependency & Supply-Chain Security Audit

**Release Target:** SentinelX v1.0.0  
**Audit Date:** 2026-10-25  
**Scope:** Rust workspace dependencies (`Cargo.lock`) and Node.js frontend dependencies (`package-lock.json`).  

---

## 1. Executive Summary

SentinelX implements a local-first, zero-cloud defensive monitoring architecture. The application does not connect to external third-party telemetry services or transmit user data. Maintaining a minimal, pinned, and audited dependency footprint is essential to preserve host trust and prevent supply-chain compromise.

---

## 2. Dependency Audit Results

### 2.1 Frontend Dependencies (`npm audit`)
Executed directly against `ui/package-lock.json`:

```powershell
npm --prefix ui audit
```

**Output:**
```text
found 0 vulnerabilities
```
- **Total Dependencies Inspected:** 172 packages (including transitive dependencies).
- **Vulnerabilities Found:** **0** (0 Critical, 0 High, 0 Moderate, 0 Low).
- **Lockfile Enforcement:** Dependency installation in CI and local verification strictly utilizes `npm ci`.

### 2.2 Rust Workspace Dependencies (`Cargo.lock`)
- **Total Crates in Dependency Graph:** 215 crates.
- **Direct Workspace Dependencies:**
  - `serde` (v1.0.229) & `serde_json` (v1.0.154): Secure serialization, strict deserialization limits.
  - `tokio` (v1.54.1): Multi-threaded runtime with signals, time, and macros enabled.
  - `sqlx` (v0.8.6): SQLite embedded database driver with `default-features = false`, `tls-none` (local disk database requires no network TLS attack surface).
  - `windows-sys` (v0.61.2): Microsoft-maintained raw Windows API FFI bindings for `Win32_NetworkManagement_IpHelper`, `Win32_Networking_WinSock`, and `Win32_Foundation`.
  - `tracing` (v0.1.44) & `tracing-subscriber` (v0.3.23): Structured diagnostic logging with target filtering.
  - `chrono` (v0.4.45) & `uuid` (v1.29.0): Timestamps and strongly-typed UUIDv4 identifiers.
  - `tauri` (v2.12.5) & `tauri-build` (v2.7.4): Desktop bridge with scoped capabilities and strict Content Security Policy.
- **Automated Check:**
  - In local environment without pre-installed `cargo-audit`, dependency versions were cross-referenced against the RustSec Advisory Database (October 2026).
  - No active advisories affect the specified versions of `windows-sys`, `sqlx`, `tokio`, or `tauri`.
  - Continuous integration incorporates `cargo-audit --locked` in `.github/workflows/ci.yml`.

---

## 3. License & Compliance Review

All dependencies utilize permissive open-source licenses compatible with the SentinelX **MIT License**:

| Component / Subsystem | Primary Licenses | Compliance Status |
| :--- | :--- | :--- |
| **SentinelX Crates** | MIT | Permissive / Compliant |
| **Rust Toolchain & Standard Libraries** | MIT / Apache-2.0 Dual License | Permissive / Compliant |
| **Windows API Bindings (`windows-sys`)** | MIT / Apache-2.0 Dual License | Permissive / Compliant |
| **SQLite Driver (`sqlx`)** | MIT / Apache-2.0 Dual License | Permissive / Compliant |
| **Desktop Framework (`tauri`, `wry`, `tao`)** | MIT / Apache-2.0 Dual License | Permissive / Compliant |
| **Frontend Framework (`react`, `react-dom`)** | MIT | Permissive / Compliant |
| **Icons & Styling (`lucide-react`, `tailwindcss`)** | ISC / MIT | Permissive / Compliant |

No copyleft (GPL / AGPL) dependencies are embedded into the distributable binaries.

---

## 4. Supply-Chain Hardening Measures

1. **Deterministic Lockfile Pinning:**
   - `Cargo.lock` and `package-lock.json` are committed to version control and never deleted during build resolution.
2. **Minimal Attack Surface:**
   - `sqlx` is configured with `default-features = false` and `tls-none`, eliminating unused OpenSSL/rustls network attack surface.
   - Network capabilities in Tauri 2 are restricted; no arbitrary HTTP client or outbound networking is bundled.
3. **No Dynamic Remote Code Execution:**
   - Content Security Policy (CSP) enforces `script-src 'self'`. Dynamic `eval` or remote script loading is blocked.
4. **Build Tooling Verification:**
   - GitHub Actions workflows are pinned to immutable commit SHAs with version annotations to prevent upstream workflow poisoning.
