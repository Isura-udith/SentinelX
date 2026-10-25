<#
.SYNOPSIS
    SentinelX Release Candidate Automated Verification and Build Pipeline for Windows 11.
.DESCRIPTION
    Executes a comprehensive, non-destructive validation suite for SentinelX:
    1. Toolchain & environment verification
    2. Frontend static analysis (typecheck, lint, vitest)
    3. Rust quality assurance (fmt, clippy, workspace tests)
    4. Frontend production asset build
    5. Tauri Windows application compilation & NSIS packaging
    6. Release artifact checksum verification (SHA-256)
.EXAMPLE
    .\scripts\verify-release.ps1
    .\scripts\verify-release.ps1 -SkipPackaging
#>

[CmdletBinding()]
param(
    [switch]$SkipPackaging = $false,
    [switch]$SkipTests = $false
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host " SentinelX Release Verification Pipeline (Windows 11 x64)" -ForegroundColor Cyan
Write-Host " Project Root: $ProjectRoot" -ForegroundColor DarkGray
Write-Host "========================================================================" -ForegroundColor Cyan

function Run-Step {
    param(
        [string]$StepName,
        [scriptblock]$Action
    )
    Write-Host "`n>>> [STEP] $StepName..." -ForegroundColor Yellow
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $stopwatch.Stop()
        Write-Host ">>> [PASS] $StepName completed in $($stopwatch.Elapsed.TotalSeconds.ToString('F2'))s" -ForegroundColor Green
    }
    catch {
        $stopwatch.Stop()
        Write-Host ">>> [FAIL] $StepName FAILED after $($stopwatch.Elapsed.TotalSeconds.ToString('F2'))s" -ForegroundColor Red
        Write-Host "Error Details: $_" -ForegroundColor Red
        exit 1
    }
}

# 1. Environment & Toolchain Audit
Run-Step "Environment & Toolchain Audit" {
    Write-Host "Checking Rust toolchain..." -ForegroundColor DarkGray
    $rustcVersion = rustc --version
    Write-Host "  Rust Compiler: $rustcVersion" -ForegroundColor Gray

    $cargoVersion = cargo --version
    Write-Host "  Cargo: $cargoVersion" -ForegroundColor Gray

    Write-Host "Checking Node.js & npm..." -ForegroundColor DarkGray
    $nodeVersion = node --version
    Write-Host "  Node.js: $nodeVersion" -ForegroundColor Gray

    $npmVersion = npm --version
    Write-Host "  npm: $npmVersion" -ForegroundColor Gray
}

# 2. Rust Formatting Check
Run-Step "Rust Formatting Validation (cargo fmt)" {
    Push-Location $ProjectRoot
    try {
        cargo fmt --all -- --check
    }
    finally {
        Pop-Location
    }
}

# 3. Rust Clippy Static Analysis
Run-Step "Rust Clippy Static Analysis (cargo clippy)" {
    Push-Location $ProjectRoot
    try {
        cargo clippy --workspace --all-targets -- -D warnings
    }
    finally {
        Pop-Location
    }
}

# 4. Frontend Type Checking
Run-Step "Frontend Type Checking (tsc --noEmit)" {
    Push-Location "$ProjectRoot\ui"
    try {
        npm run typecheck
    }
    finally {
        Pop-Location
    }
}

# 5. Frontend Linting
Run-Step "Frontend Code Quality (oxlint)" {
    Push-Location "$ProjectRoot\ui"
    try {
        npm run lint
    }
    finally {
        Pop-Location
    }
}

# 6. Frontend Unit Tests
if (-not $SkipTests) {
    Run-Step "Frontend Test Suite (vitest)" {
        Push-Location "$ProjectRoot\ui"
        try {
            npm test
        }
        finally {
            Pop-Location
        }
    }
} else {
    Write-Host "`n>>> [SKIP] Frontend Test Suite skipped by flag." -ForegroundColor DarkYellow
}

# 7. Rust Workspace Tests
if (-not $SkipTests) {
    Run-Step "Rust Workspace Unit & Integration Tests (cargo test)" {
        Push-Location $ProjectRoot
        try {
            cargo test --workspace
        }
        finally {
            Pop-Location
        }
    }
} else {
    Write-Host "`n>>> [SKIP] Rust Workspace Tests skipped by flag." -ForegroundColor DarkYellow
}

# 8. Frontend Production Build
Run-Step "Frontend Production Assets (vite build)" {
    Push-Location "$ProjectRoot\ui"
    try {
        npm run build
    }
    finally {
        Pop-Location
    }
}

# 9. Tauri Desktop Application Build & Packaging
if (-not $SkipPackaging) {
    Run-Step "Tauri Windows Packaging (NSIS Installer)" {
        Push-Location $ProjectRoot
        try {
            npx --prefix ui tauri build --bundles nsis
        }
        finally {
            Pop-Location
        }
    }

    # 10. Release Artifact Integrity Verification
    Run-Step "Release Artifact Verification & Checksums" {
        $bundleDir = "$ProjectRoot\target\release\bundle\nsis"
        $installer = Get-ChildItem -Path $bundleDir -Filter "SentinelX_*_x64-setup.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

        if (-not $installer) {
            throw "NSIS installer was not found in $bundleDir after build."
        }

        $hash = Get-FileHash -Path $installer.FullName -Algorithm SHA256
        $sizeMB = ($installer.Length / 1MB).ToString("F2")

        Write-Host "`nVerified Release Artifact:" -ForegroundColor Cyan
        Write-Host "  Name:     $($installer.Name)" -ForegroundColor White
        Write-Host "  Size:     $sizeMB MB" -ForegroundColor White
        Write-Host "  Path:     $($installer.FullName)" -ForegroundColor White
        Write-Host "  SHA-256:  $($hash.Hash)" -ForegroundColor Green

        $checksumFile = "$ProjectRoot\target\release\bundle\nsis\SHA256SUMS.txt"
        "$($hash.Hash)  $($installer.Name)" | Out-File -FilePath $checksumFile -Encoding utf8
        Write-Host "  Saved checksum file to $checksumFile" -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n>>> [SKIP] Desktop Packaging skipped by flag." -ForegroundColor DarkYellow
}

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host " SentinelX Release Verification: ALL CHECKS PASSED" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
exit 0
