# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 ArchCracker contributors
#
# W2-008 local benchmark harness: 1M candidates per attack mode on synthetic
# ZIP AES fixtures. Writes only a JSON report under tests/corpus/out/.
# No archive/dictionary is committed.

param(
    [string]$Exe = "",
    [int]$Threads = 14
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$out = Join-Path $root 'tests/corpus/out'
if (-not $Exe) { $Exe = Join-Path $root 'core/target/release/acx.exe' }
if (-not (Test-Path $Exe)) { throw "release binary missing: $Exe" }

function New-BenchFixture([string]$directory, [string]$password) {
    $dir = Join-Path $out $directory
    if (-not (Test-Path (Join-Path $dir 'aes.zip'))) {
        Push-Location (Join-Path $root 'core')
        try {
            & cargo run -q -p acx-cli --example w2_008_fixtures -- (Join-Path $root "tests/corpus/out/$directory") $password | Out-Null
        }
        finally { Pop-Location }
    }
    return Join-Path $dir 'aes.zip'
}

function Measure-Run([string]$name, [string]$archive, [string[]]$extra) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Exe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $allArgs = @('-f', $archive, '-t', "$Threads", '--report-stats') + $extra
    $quoted = $allArgs | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }
    $psi.Arguments = $quoted -join ' '

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $cpu = [timespan]::Zero
    $rss = 0L
    while (-not $process.HasExited) {
        try {
            $process.Refresh()
            $current = $process.TotalProcessorTime
            if ($current -gt $cpu) { $cpu = $current }
            $working = $process.WorkingSet64
            if ($working -gt $rss) { $rss = $working }
        }
        catch { }
        Start-Sleep -Milliseconds 100
    }
    $process.WaitForExit()
    $watch.Stop()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()

    $attempts = [regex]::Match($stdout, 'encoding attempts=(\d+)').Groups[1].Value
    $attemptsValue = 0L
    [void][long]::TryParse($attempts, [ref]$attemptsValue)
    $seconds = $watch.Elapsed.TotalSeconds
    $rate = if ($seconds -gt 0) { $attemptsValue / $seconds } else { 0.0 }

    return [pscustomobject]@{
        name             = $name
        exit_code        = $process.ExitCode
        found            = $stdout.Contains('FOUND:')
        wall_seconds     = [math]::Round($seconds, 3)
        attempts         = $attemptsValue
        candidates_per_s = [math]::Round($rate, 1)
        cpu_seconds      = [math]::Round($cpu.TotalSeconds, 3)
        peak_rss_bytes   = $rss
        stats            = ($stdout -split "`n" | Where-Object { $_ -like 'Stats:*' } | Select-Object -First 1)
        stderr_tail      = ($stderr -split "`n" | Select-Object -Last 3) -join ' | '
    }
}

$results = @()
$results += Measure-Run 'dict_1m' (Join-Path $out 'fixtures/aes.zip') @('-d', (Join-Path $out 'dictionaries/dict_1m.txt'))
$results += Measure-Run 'mask_1m' (New-BenchFixture 'bench_mask' '123456') @('--mask', '?d?d?d?d?d?d')
$results += Measure-Run 'brute_1m' (Join-Path $out 'bench_mask/aes.zip') @('--brute', '?d', '--min-len', '1', '--max-len', '6')
$results += Measure-Run 'hybrid_1m' (New-BenchFixture 'bench_hybrid' 'w0999999') @('-d', (Join-Path $out 'dictionaries/dict_hybrid_1k.txt'), '--suffix-mask', '?d?d?d')

$report = [pscustomobject]@{
    generated_utc = [DateTime]::UtcNow.ToString('o')
    exe           = $Exe
    threads       = $Threads
    platform      = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    note          = 'Synthetic small-entry ZIP AES fixtures; not comparable with W1 1 GB baselines.'
    results       = $results
}
$target = Join-Path $out 'bench-raw.json'
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $target -Encoding UTF8
$results | Format-Table name, exit_code, found, wall_seconds, attempts, candidates_per_s, peak_rss_bytes -AutoSize
Write-Host "raw report: $target"
