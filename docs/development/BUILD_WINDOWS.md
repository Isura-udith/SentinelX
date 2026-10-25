# SentinelX Build & Development Guide for Windows 11

This guide documents the complete, reproducible process for setting up a clean Windows 11 development workstation and building the SentinelX desktop application and its distribution installer.

---

## 1. System Requirements & Prerequisites

### 1.1 Operating System
- **Target OS:** Windows 11 (64-bit, Version 22H2 or newer recommended).
- **Architecture:** x86_64 (`x86_64-pc-windows-msvc`).
- **Permissions:** Standard user privileges for building and running. Administrative privileges are **not** required for development or for running the per-user NSIS installer.

### 1.2 Toolchain & Compilers
1. **Visual Studio C++ Build Tools:**
   - Visual Studio 2022 or Build Tools 2022/2026.
   - Workload: **Desktop development with C++**.
   - Mandatory components: MSVC v143/v144 x64/x86 build tools, Windows 10/11 SDK (provides `iphlpapi.lib` and `ws2_32.lib` for IP Helper FFI).

2. **Rust Toolchain:**
   - Managed via `rustup`.
   - Toolchain: `stable-x86_64-pc-windows-msvc` (edition 2024, Rust 1.85+; verified on Rust 1.99.1).
   - Components: `rustfmt`, `clippy`.
   - Workspace configuration is pinned via `rust-toolchain.toml`.

3. **Node.js & npm:**
   - Node.js LTS: Version 20.x or newer (tested with Node v24.14.0).
   - npm: Version 10.x or newer (tested with npm v11.9.0).

4. **Microsoft Edge WebView2 Runtime:**
   - Embedded evergreen runtime standard on all Windows 11 installations.
   - Tested runtime version: `155.0.4283.62`.

5. **Windows Packaging Engine:**
   - Tauri 2 CLI automatically downloads and caches NSIS (`makensis`) when generating `.exe` setup packages. No manual NSIS installation is needed.

---

## 2. Repository Setup

Clone the repository and enter the project root:

```powershell
git clone https://github.com/sentinelx/sentinelx.git
cd sentinelx
```

### 2.1 Installing Frontend Dependencies
Always install dependencies strictly from `package-lock.json` to prevent dependency drift:

```powershell
cd ui
npm ci
cd ..
```

---

## 3. Step-by-Step Validation & Build Commands

### Step 1: Frontend Type Checking
Validates TypeScript compilation without emitting JavaScript:
```powershell
npm --prefix ui run typecheck
```

### Step 2: Frontend Code Quality & Linting
Runs `oxlint` across React and TypeScript sources:
```powershell
npm --prefix ui run lint
```

### Step 3: Frontend Unit Tests
Executes Vitest component and service tests:
```powershell
npm --prefix ui run test
```

### Step 4: Rust Code Formatting Validation
Ensures formatting matches Rust standard guidelines:
```powershell
cargo fmt --all -- --check
```

### Step 5: Rust Static Analysis (Clippy)
Runs strict static analysis across all workspace members, targets, and integration tests:
```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

### Step 6: Rust Unit & Integration Tests
Runs the full automated Rust test suite:
```powershell
cargo test --workspace
```
*Expected output: All 55+ unit, integration, and property-based tests pass cleanly.*

### Step 7: Build Production Frontend Assets
Compiles TypeScript and bundles React assets into `ui/dist`:
```powershell
npm --prefix ui run build
```

### Step 8: Build Tauri Desktop Executable (No Bundle)
Compiles the release binary `sentinel-app.exe`:
```powershell
npx --prefix ui tauri build --no-bundle
```
*Output binary located at:* `target\release\sentinel-app.exe`

### Step 9: Generate Windows NSIS Installer Package
Packages the application into a standalone Windows installer:
```powershell
npx --prefix ui tauri build --bundles nsis
```
*Output installer located at:* `target\release\bundle\nsis\SentinelX_1.0.0_x64-setup.exe`

---

## 4. Single-Command Automated Verification

To run all static checks, unit tests, integration tests, release compilation, and installer verification in an automated pipeline, run:

```powershell
.\scripts\verify-release.ps1
```

Options:
- `-SkipPackaging`: Runs all static checks and tests without building the release installer bundle.
- `-SkipTests`: Runs build and packaging verification while bypassing test execution.

---

## 5. Clean Builds & Cache Invalidation

If experiencing transient cache issues, perform a safe clean without deleting local user databases:

```powershell
# Clean Rust build artifacts
cargo clean

# Recompile release binary
cargo build --workspace --release
```

Do not delete lockfiles (`Cargo.lock`, `package-lock.json`) as they guarantee deterministic dependency resolution.
