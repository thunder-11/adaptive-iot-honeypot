$ErrorActionPreference = 'Stop'
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\run_all.ps1') @args
