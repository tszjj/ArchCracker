# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 ArchCracker contributors
#
# ArchCracker Windows bootstrap (user-scope, no administrator required).
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1
# Installs: MinGW-w64 (WinLibs), CMake, GitHub CLI, Rust (GNU toolchain), .NET 10 SDK.
# Android/HarmonyOS SDKs are intentionally NOT downloaded here (deferred).

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$PS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Have([string]$cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

function Add-PathEntries([string[]]$entries) {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $all = @()
    if ($machine) { $all += ($machine -split ';' | Where-Object { $_ }) }
    if ($user) { $all += ($user -split ';' | Where-Object { $_ }) }
    if ($env:Path) { $all += ($env:Path -split ';' | Where-Object { $_ }) }
    $all += $entries
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $clean = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $all) { if ($p -and $seen.Add($p)) { [void]$clean.Add($p) } }
    $env:Path = ($clean -join ';')
    return $clean
}

function Winget-Install([string]$id) {
    Write-Host "==> winget install $id (user scope)" -ForegroundColor Cyan
    winget install --id $id --exact --scope user --source winget `
        --accept-package-agreements --accept-source-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "winget $id returned $LASTEXITCODE (may already be installed or need retry)"
    }
}

Write-Host 'ArchCracker Windows bootstrap' -ForegroundColor Green
Write-Host 'No administrator rights are requested; everything goes to the user profile.'
Write-Host ''

if (-not (Have 'winget')) {
    Write-Error 'winget is required. Install App Installer from the Microsoft Store first.'
    exit 1
}

if (-not (Have 'gcc')) { Winget-Install 'BrechtSanders.WinLibs.POSIX.UCRT' }
if (-not (Have 'cmake')) { Winget-Install 'Kitware.CMake' }
if (-not (Have 'gh')) { Winget-Install 'GitHub.cli' }

# Re-read user PATH so winget-installed tools are visible; keep the machine PATH too.
[void](Add-PathEntries @())

# --- Rust (GNU host, uses MinGW linker) ---
if (-not (Have 'cargo')) {
    Write-Host '==> installing Rust (x86_64-pc-windows-gnu)' -ForegroundColor Cyan
    $rustup = Join-Path $env:TEMP 'rustup-init.exe'
    $shaUrl = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe.sha256'
    Invoke-WebRequest -Uri 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe' `
        -OutFile $rustup -UseBasicParsing
    try {
        $expected = (Invoke-WebRequest -Uri $shaUrl -UseBasicParsing).Content.Trim().Split(' ')[0]
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $rustup).Hash.ToLowerInvariant()
        if ($expected.ToLowerInvariant() -ne $actual) {
            throw "rustup-init SHA-256 mismatch: expected $expected, got $actual"
        }
        Write-Host 'rustup-init SHA-256 verified' -ForegroundColor Green
    } catch {
        Write-Warning "rustup-init hash verification failed or unavailable: $($_.Exception.Message)"
    }
    $env:RUSTUP_HOME = Join-Path $env:USERPROFILE '.rustup'
    $env:CARGO_HOME = Join-Path $env:USERPROFILE '.cargo'
    & $rustup -y --default-host x86_64-pc-windows-gnu --profile minimal --no-modify-path
    if (-not (Have 'cargo')) {
        Write-Warning 'rustup-init did not finish; trying toolchain install explicitly'
        & (Join-Path $env:CARGO_HOME 'bin\rustup.exe') toolchain install stable-x86_64-pc-windows-gnu --profile minimal
        & (Join-Path $env:CARGO_HOME 'bin\rustup.exe') default stable-x86_64-pc-windows-gnu
    }
    [void](Add-PathEntries @((Join-Path $env:USERPROFILE '.cargo\bin')))
    & (Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe') component add rustfmt clippy
}

# --- .NET 10 SDK (user-local) ---
$dotnetHome = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet'
$sdkOk = $false
if (Have 'dotnet') {
    $sdks = & dotnet --list-sdks 2>$null
    $sdkOk = [bool]($sdks | Where-Object { $_ -match '^10\.' })
}
if (-not $sdkOk) {
    Write-Host '==> installing .NET 10 SDK (user-local)' -ForegroundColor Cyan
    $installer = Join-Path $env:TEMP 'dotnet-install.ps1'
    Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installer -UseBasicParsing
    # Note: this is a Microsoft-hosted bootstrap script; pin its hash in CI/release builds.
    & $PS -NoProfile -ExecutionPolicy Bypass -File $installer -Channel 10.0 -InstallDir $dotnetHome -NoPath
    [void](Add-PathEntries @($dotnetHome))
}

# --- Persist user PATH (idempotent, no trailing empty entry) ---
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$add = @(
    (Join-Path $env:USERPROFILE '.cargo\bin'),
    $dotnetHome
)
$parts = @()
if ($userPath) { $parts += ($userPath -split ';' | Where-Object { $_ -ne '' }) }
foreach ($p in $add) { if ($parts -notcontains $p) { $parts += $p } }
[Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')

Write-Host ''
Write-Host 'Verifying...' -ForegroundColor Cyan
& $PS -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'check-env.ps1')
$code = $LASTEXITCODE

Write-Host ''
Write-Host 'Next:' -ForegroundColor Green
Write-Host '  Set-ExecutionPolicy -Scope Process Bypass -Force'
Write-Host '  . .\scripts\env.ps1'
Write-Host '  cargo --version'
Write-Host '  dotnet --version'
Write-Host '  gh auth login        # then create/push the GitHub repo'
Write-Host ''
Write-Host 'Windows full-stack first: core + CLI + Avalonia + installer.'
Write-Host 'Android/HarmonyOS SDKs are deferred until after the Windows release.'
exit $code
