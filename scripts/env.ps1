# ArchCracker dev environment for the current PowerShell session.
# Usage:  . .\scripts\env.ps1
# Safe to source repeatedly; it does not install anything.

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

$env:RUSTUP_HOME = Join-Path $env:USERPROFILE '.rustup'
$env:CARGO_HOME = Join-Path $env:USERPROFILE '.cargo'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

Write-Host "ArchCracker env loaded."
Write-Host ("  cargo : " + (Get-Command cargo).Source)
Write-Host ("  rustc : " + (Get-Command rustc).Source)
Write-Host ("  gcc   : " + (Get-Command gcc).Source)
Write-Host ("  cmake : " + (Get-Command cmake).Source)
Write-Host ("  dotnet: " + (Get-Command dotnet).Source)
