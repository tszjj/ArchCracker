# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 ArchCracker contributors
#
# ArchCracker dev environment for the current PowerShell session.
# Usage:  Set-ExecutionPolicy -Scope Process Bypass -Force
#         . .\scripts\env.ps1
# Safe to source repeatedly; it does not install anything.

$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$homeCargo = Join-Path $env:USERPROFILE '.cargo\bin'
$dotnetHome = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet'

$parts = @($homeCargo, $dotnetHome)
if ($userPath) { $parts += ($userPath -split ';' | Where-Object { $_ -ne '' }) }
if ($env:Path) { $parts += ($env:Path -split ';' | Where-Object { $_ -ne '' }) }

$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$clean = New-Object 'System.Collections.Generic.List[string]'
foreach ($p in $parts) {
    if ($p -and $seen.Add($p)) { [void]$clean.Add($p) }
}
$env:Path = ($clean -join ';')

# Do not override an existing custom toolchain location.
if (-not $env:RUSTUP_HOME) { $env:RUSTUP_HOME = Join-Path $env:USERPROFILE '.rustup' }
if (-not $env:CARGO_HOME) { $env:CARGO_HOME = Join-Path $env:USERPROFILE '.cargo' }
if (-not $env:DOTNET_ROOT -and (Test-Path $dotnetHome)) { $env:DOTNET_ROOT = $dotnetHome }
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

function Show-Cmd([string]$Name) {
    $c = Get-Command $Name -ErrorAction SilentlyContinue
    if ($c) { Write-Host ("  {0,-7}: {1}" -f $Name, $c.Source) }
    else { Write-Host ("  {0,-7}: (missing)" -f $Name) -ForegroundColor Yellow }
}

Write-Host 'ArchCracker env loaded.'
Show-Cmd 'cargo'
Show-Cmd 'rustc'
Show-Cmd 'gcc'
Show-Cmd 'cmake'
Show-Cmd 'dotnet'

$ErrorActionPreference = $previousPreference
