# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 ArchCracker contributors
#
# Install the local pre-push guard into .git/hooks. This is a local-only
# safeguard; it is not a substitute for GitHub branch protection.

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $root '.githooks/pre-push'
$target = Join-Path $root '.git/hooks/pre-push'

if (-not (Test-Path $source)) { throw "missing hook source: $source" }
Copy-Item -Path $source -Destination $target -Force
Write-Host "installed pre-push guard: $target"
Write-Host "note: this guard is local only; other clones are unaffected."
