# ArchCracker environment check (read-only).
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\check-env.ps1
# Exit code 0 = core toolchain OK; 1 = missing core tool.

$ErrorActionPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'env.ps1') | Out-Null

function Show-Tool([string]$Name, [string]$Command, [string]$VersionArg = '--version') {
    $cmd = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host ("[MISS] {0,-12} {1}" -f $Name, $Command) -ForegroundColor Yellow
        return $false
    }
    $v = & $Command $VersionArg 2>&1 | Select-Object -First 1
    Write-Host ("[ OK ] {0,-12} {1}" -f $Name, $v) -ForegroundColor Green
    return $true
}

$ok = $true
$ok = (Show-Tool 'git'    'git'    '--version') -and $ok
$ok = (Show-Tool 'rustc'  'rustc'  '--version') -and $ok
$ok = (Show-Tool 'cargo'  'cargo'  '--version') -and $ok
$ok = (Show-Tool 'gcc'    'gcc'    '--version') -and $ok
$ok = (Show-Tool 'cmake'  'cmake'  '--version') -and $ok
$ok = (Show-Tool 'ninja'  'ninja'  '--version') -and $ok
$ok = (Show-Tool 'dotnet' 'dotnet' '--version') -and $ok
$ok = (Show-Tool 'gh'     'gh'     '--version') -and $ok

Write-Host ''
Write-Host 'SDKs (optional, needed for P3+):'
$androidSdk = $env:ANDROID_HOME
if (-not $androidSdk) { $androidSdk = $env:ANDROID_SDK_ROOT }
if (-not $androidSdk) { $androidSdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
if (Test-Path $androidSdk) { Write-Host ("[ OK ] Android SDK  " + $androidSdk) -ForegroundColor Green }
else { Write-Host '[ -- ] Android SDK  not installed (P3)' -ForegroundColor DarkGray }

$ndk = $env:ANDROID_NDK_HOME
if ($ndk -and (Test-Path $ndk)) { Write-Host ("[ OK ] Android NDK  " + $ndk) -ForegroundColor Green }
else { Write-Host '[ -- ] Android NDK  not installed (P3)' -ForegroundColor DarkGray }

$deveco = @(
    'C:\Program Files\Huawei\DevEco Studio',
    'C:\Program Files\DevEco Studio',
    (Join-Path $env:LOCALAPPDATA 'Huawei\DevEco Studio')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($deveco) { Write-Host ("[ OK ] DevEco      " + $deveco) -ForegroundColor Green }
else { Write-Host '[ -- ] DevEco      not installed (P4)' -ForegroundColor DarkGray }

Write-Host ''
Write-Host 'Rust targets:'
& rustup target list --installed 2>$null | ForEach-Object { Write-Host ("  " + $_) }

if (-not $ok) {
    Write-Host ''
    Write-Host 'Core toolchain incomplete. Run scripts/bootstrap-windows.ps1' -ForegroundColor Yellow
    exit 1
}

Write-Host ''
Write-Host 'Core toolchain OK.' -ForegroundColor Green
exit 0
