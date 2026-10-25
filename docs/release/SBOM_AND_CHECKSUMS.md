# SentinelX Software Bill of Materials (SBOM) & Checksums

**Release:** SentinelX v1.0.0 (Release Candidate / Initial Public Release)  
**Target Platform:** Windows 11 x64 (`x86_64-pc-windows-msvc`)  
**Publication Date:** 2026-10-25  

---

## 1. Verified Release Artifact Hashes (SHA-256)

All cryptographic checksums below are computed directly from the verified production binaries produced during clean release compilation:

| Filename | Architecture | File Size (Bytes) | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **`SentinelX_1.0.0_x64-setup.exe`** | x86_64 | 3,960,074 | `63A86984E27B419F28A5AC4EECDA77B59EE189222BB3E186BA541026F2B81BE0` |
| **`sentinel-app.exe`** | x86_64 | 16,228,864 | `C0D9DAC824621BAC72D9838AB2C022D7BB327AC70DFD71F25D732DC8C9BF7C5A` |

---

## 2. Checksum Verification Instructions

### Windows PowerShell
To verify the integrity of the downloaded installer before running setup:

```powershell
# Compute SHA-256 hash
$computedHash = (Get-FileHash .\SentinelX_1.0.0_x64-setup.exe -Algorithm SHA256).Hash
$expectedHash = "63A86984E27B419F28A5AC4EECDA77B59EE189222BB3E186BA541026F2B81BE0"

if ($computedHash -eq $expectedHash) {
    Write-Host "[SUCCESS] Installer checksum verified successfully." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Checksum MISMATCH! File may be corrupted or tampered with." -ForegroundColor Red
}
```

### Linux / WSL / Bash
```bash
sha256sum -c SHA256SUMS.txt
```

> **Security Note:** A cryptographic checksum verifies file integrity and guards against corruption and transmission tampering. It verifies authenticity only when compared against a trusted, independently obtained checksum source.

---

## 3. Software Bill of Materials (SBOM)

A machine-readable Software Bill of Materials is provided in standard CycloneDX JSON format:
- **Location:** `docs/release/SBOM.json`
- **Specification:** CycloneDX v1.5
- **Serial Number:** `urn:uuid:3acd2496-9a5a-42fd-b3d7-9a6c9eb6442e`
- **Scope:** Complete tree of direct and transitively linked runtime libraries for Rust core, SQLite engine, Windows IP Helper bindings, Tauri 2 desktop bridge, and React frontend assets.

### Key Top-Level Components
1. **`sentinel-core` (v1.0.0):** Strongly-typed security event and alert domain models.
2. **`sentinel-collector` (v1.0.0):** Windows IP Helper TCP snapshot telemetry collector.
3. **`sentinel-detection` (v1.0.0):** Stateful rolling-window defensive detection engine.
4. **`sentinel-storage` (v1.0.0):** SQLite persistence layer with compile-time embedded migrations.
5. **`sentinel-app` (v1.0.0):** Tauri 2 desktop application coordinator.
6. **`windows-sys` (v0.61.2):** Microsoft raw Windows FFI bindings.
7. **`sqlx` (v0.8.6):** Embedded async SQLite driver.
8. **`tokio` (v1.54.1):** Asynchronous task executor.
9. **`react` & `react-dom` (v19.3.1):** Frontend dashboard presentation library.

---

## 4. Code Signing & SmartScreen Disclosure

- **Signing Status:** **Unsigned Development Release Candidate**.
- **Explanation:** SentinelX is an independent educational defensive security project. It is not currently signed with a commercial Microsoft Extended Validation (EV) Code Signing Certificate.
- **Expected User Experience:** On fresh execution on Windows 11, Windows Defender SmartScreen will display an *"Unknown Publisher"* blue dialog.
- **Guidance:** Users should verify the SHA-256 hash against this document and proceed via **More info > Run anyway**. Enterprise deployments may sign the binary internally using their organization's Code Signing PKI.
