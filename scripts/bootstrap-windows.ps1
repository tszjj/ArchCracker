# ArchCracker Windows bootstrap (user-scope, no administrator required).
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1
# Installs: MinGW-w64 (WinLibs), CMake, GitHub CLI, Rust (GNU toolchain), .NET 10 SDK.
# Android/HarmonyOS SDKs are intentionally NOT downloaded here (multi-GB, P3/P4).

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Have([string]$cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

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

# Re-read the user PATH so tools installed by winget are visible in this session.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$env:Path = ($userPath -split ';' | Where-Object { $_ }) -join ';'

# --- Rust (GNU host, uses MinGW linker) ---
if (-not (Have 'cargo')) {
    Write-Host '==> installing Rust (x86_64-pc-windows-gnu)' -ForegroundColor Cyan
    $rustup = Join-Path $env:TEMP 'rustup-init.exe'
    Invoke-WebRequest -Uri 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe' `
        -OutFile $rustup -UseBasicParsing
    $env:RUSTUP_HOME = Join-Path $env:USERPROFILE '.rustup'
    $env:CARGO_HOME = Join-Path $env:USERPROFILE '.cargo'
    & $rustup -y --default-host x86_64-pc-windows-gnu --profile minimal --no-modify-path
    if (-not (Have 'cargo')) {
        Write-Warning 'rustup-init did not finish; trying toolchain install explicitly'
        & (Join-Path $env:CARGO_HOME 'bin\rustup.exe') toolchain install stable-x86_64-pc-windows-gnu --profile minimal
        & (Join-Path $env:CARGO_HOME 'bin\rustup.exe') default stable-x86_64-pc-windows-gnu
    }
    $env:Path = (Join-Path $env:USERPROFILE '.cargo\bin') + ';' + $env:Path
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
    & powershell -NoProfile -ExecutionPolicy Bypass -File $installer -Channel 10.0 -InstallDir $dotnetHome -NoPath
    $env:Path = $dotnetHome + ';' + $env:Path
}

# --- Persist user PATH (idempotent) ---
$add = @(
    (Join-Path $env:USERPROFILE '.cargo\bin'),
    $dotnetHome
)
$parts = @()
if ($userPath) { $parts += ($userPath -split ';' | Where-Object { $_ -ne '' }) }
foreach ($p in $add) { if ($parts -notcontains $p) { $parts += $p } }
[Environment]::SetEnvironmentVariable('Path', (($parts -join ';') + ';'), 'User')

Write-Host ''
Write-Host 'Verifying...' -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'check-env.ps1')
$code = $LASTEXITCODE

Write-Host ''
Write-Host 'Next:' -ForegroundColor Green
Write-Host '  . .\scripts\env.ps1'
Write-Host '  cargo --version'
Write-Host '  dotnet --version'
Write-Host '  gh auth login        # then create/push the GitHub repo'
Write-Host ''
Write-Host 'Android SDK/NDK: install Android Studio or command-line tools (P3).'
Write-Host 'HarmonyOS: install DevEco Studio + SDK (P4); no automatic download here.'
exit $code
