# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 ArchCracker contributors
#
# Reproducible W1 CLI benchmark runner.
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/bench-w1.ps1 `
#     -Archive <archive> -Dictionary <dict> -Threads 14 -Label zip-1m `
#     -Checkpoint target/bench.zip.checkpoint
#
# It measures wall time, peak working set, process CPU time and reports JSON.
# The dictionary/archive remain local and are not written by this script.

param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Dictionary,
    [int]$Threads = 14,
    [string]$Label = "run",
    [string]$Checkpoint = "",
    [int]$TimeoutSeconds = 0
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "core\target\release\acx.exe"
if (-not (Test-Path $exe)) {
    throw "release binary missing: $exe (run cargo build --workspace --release)"
}
if (-not (Test-Path $Archive)) { throw "archive missing: $Archive" }
if (-not (Test-Path $Dictionary)) { throw "dictionary missing: $Dictionary" }
if ([string]::IsNullOrWhiteSpace($Checkpoint)) {
    $Checkpoint = Join-Path $env:TEMP "acx-bench-$Label-$PID.acx-checkpoint"
}
Remove-Item $Checkpoint, "$Checkpoint.lock" -Force -ErrorAction SilentlyContinue

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $exe
$psi.WorkingDirectory = $root
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.Arguments = '-f "' + (Resolve-Path $Archive).Path + '" -d "' +
    (Resolve-Path $Dictionary).Path + '" --checkpoint "' + $Checkpoint +
    '" -t ' + $Threads

$watch = [System.Diagnostics.Stopwatch]::StartNew()
$process = [System.Diagnostics.Process]::Start($psi)
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
$peak = 0L
$cpu = 0.0
$timedOut = $false

while (-not $process.HasExited) {
    try {
        $rss = $process.WorkingSet64
        if ($rss -gt $peak) { $peak = $rss }
        $cpu = [double]$process.TotalProcessorTime.TotalSeconds
    } catch { }
    if ($TimeoutSeconds -gt 0 -and $watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
        $timedOut = $true
        try { $process.Kill() } catch { }
        break
    }
    Start-Sleep -Milliseconds 200
}
$process.WaitForExit()
$watch.Stop()
$elapsed = [math]::Max($watch.Elapsed.TotalSeconds, 0.001)
$logical = [Environment]::ProcessorCount

[pscustomobject]@{
    label = $Label
    archive = (Resolve-Path $Archive).Path
    dictionary = (Resolve-Path $Dictionary).Path
    threads = $Threads
    logical_processors = $logical
    exit_code = if ($timedOut) { $null } else { $process.ExitCode }
    timed_out = $timedOut
    elapsed_sec = [math]::Round($elapsed, 3)
    peak_rss_mb = [math]::Round($peak / 1MB, 1)
    cpu_sec = [math]::Round($cpu, 3)
    cpu_pct_of_machine = [math]::Round($cpu / $elapsed * 100 / $logical, 1)
    checkpoint = $Checkpoint
    stdout = $stdoutTask.Result.Trim()
    stderr = $stderrTask.Result.Trim()
} | ConvertTo-Json -Depth 4
