# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 ArchCracker contributors
#
# ArchCracker environment check (read-only).
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\check-env.ps1
# Exit code 0 = required toolchain OK; 1 = a required tool is missing.

$ErrorActionPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'env.ps1') | Out-Null

$required = @('git', 'rustc', 'cargo')
if ($IsWindows -or $env:OS -eq 'Windows_NT') { $required += 'gcc' }
$optional = @('cmake', 'ninja', 'dotnet', 'gh')

function Show-Tool([string]$Name, [bool]$IsRequired) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $tag = if ($IsRequired) { '[MISS]' } else { '[ -- ]' }
        $color = if ($IsRequired) { 'Yellow' } else { 'DarkGray' }
        Write-Host ("{0} {1,-10} (not found)" -f $tag, $Name) -ForegroundColor $color
        return -not $IsRequired
    }
    $v = & $Name --version 2>&1 | Select-Object -First 1
    Write-Host ("[ OK ] {0,-10} {1}" -f $Name, $v) -ForegroundColor Green
    return $true
}

$ok = $true
foreach ($name in $required) { $ok = (Show-Tool $name $true) -and $ok }
foreach ($name in $optional) { [void](Show-Tool $name $false) }

Write-Host ''
Write-Host 'SDKs (optional, needed for later phases):'
$androidSdk = $env:ANDROID_HOME
if (-not $androidSdk) { $androidSdk = $env:ANDROID_SDK_ROOT }
if (-not $androidSdk) { $androidSdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
if (Test-Path $androidSdk) { Write-Host ("[ OK ] Android SDK  " + $androidSdk) -ForegroundColor Green }
else { Write-Host '[ -- ] Android SDK  not installed (deferred)' -ForegroundColor DarkGray }

$ndk = $env:ANDROID_NDK_HOME
if ($ndk -and (Test-Path $ndk)) { Write-Host ("[ OK ] Android NDK  " + $ndk) -ForegroundColor Green }
else { Write-Host '[ -- ] Android NDK  not installed (deferred)' -ForegroundColor DarkGray }

$deveco = @(
    'C:\Program Files\Huawei\DevEco Studio',
    'C:\Program Files\DevEco Studio',
    (Join-Path $env:LOCALAPPDATA 'Huawei\DevEco Studio')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($deveco) { Write-Host ("[ OK ] DevEco      " + $deveco) -ForegroundColor Green }
else { Write-Host '[ -- ] DevEco      not installed (deferred)' -ForegroundColor DarkGray }

Write-Host ''
Write-Host 'Rust targets:'
& rustup target list --installed 2>$null | ForEach-Object { Write-Host ("  " + $_) }

if (-not $ok) {
    Write-Host ''
    Write-Host 'Required toolchain incomplete. Run scripts/bootstrap-windows.ps1' -ForegroundColor Yellow
    exit 1
}

Write-Host ''
Write-Host 'Required toolchain OK.' -ForegroundColor Green
exit 0
