[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

$Root = Get-RepositoryRoot
$Run = Join-Path $Root 'run'
$StatePath = Join-Path $Run 'windows-processes.json'
$names = @('dashboard', 'proxy', 'decoy-publisher', 'decoy-broker', 'real-broker')

if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    Write-Output 'No Windows-managed stack is recorded; nothing was stopped.'
    return
}

try {
    $parsedState = Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json
    $records = @()
    foreach ($item in $parsedState) { $records += $item }
} catch {
    throw "Cannot safely stop processes because $StatePath is invalid: $($_.Exception.Message)"
}

foreach ($name in $names) {
    $record = $records | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $record) { continue }
    $process = Get-Process -Id ([int]$record.Id) -ErrorAction SilentlyContinue
    if (-not $process) { continue }

    $actualStart = $process.StartTime.ToUniversalTime()
    if ($record.PSObject.Properties.Name -contains 'StartTimeUtcTicks') {
        $sameStart = [Math]::Abs($actualStart.Ticks - [long]$record.StartTimeUtcTicks) -lt 10000000
    } else {
        $expectedStart = [DateTime]::Parse([string]$record.StartTimeUtc).ToUniversalTime()
        $sameStart = [Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -lt 1
    }
    $actualPath = $null
    try { $actualPath = $process.Path } catch {}
    $samePath = [bool]($actualPath -and
        ([System.IO.Path]::GetFullPath($actualPath) -eq [System.IO.Path]::GetFullPath([string]$record.ExecutablePath)))
    if (-not $sameStart -or -not $samePath) {
        Write-Warning "PID $($record.Id) no longer matches recorded process '$name'; it was not stopped."
        continue
    }

    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ((Get-Process -Id $process.Id -ErrorAction SilentlyContinue) -and
           [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    $stillRunning = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
    if ($stillRunning) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
}

Remove-Item -LiteralPath $StatePath -Force
foreach ($name in $names) {
    $pidFile = Join-Path $Run "$name.pid"
    if (Test-Path -LiteralPath $pidFile) { Remove-Item -LiteralPath $pidFile -Force }
}
Write-Output 'Windows-managed stack stopped.'
