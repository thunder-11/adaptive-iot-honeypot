param()
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
# Parse the shared configuration for consistency with the other lifecycle scripts.
$Config = @{}
Get-Content -LiteralPath (Join-Path $Root 'config.env') | ForEach-Object {
    $line = $_.Trim(); if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
        $key, $value = $line.Split('=', 2); $Config[$key.Trim()] = $value.Trim()
    }
}
$Run = Join-Path $Root 'run'
foreach ($name in @('dashboard', 'proxy', 'decoy-publisher', 'decoy-broker', 'real-broker')) {
    $PidFile = Join-Path $Run "$name.pid"
    if (Test-Path -LiteralPath $PidFile) {
        $ProcessId = [int](Get-Content -Raw -LiteralPath $PidFile)
        Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $PidFile -Force
    }
}
Write-Output 'Stack stopped.'
