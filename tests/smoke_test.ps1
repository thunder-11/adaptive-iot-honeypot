[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $Root 'windows\common.ps1')
$Config = Import-ConfigEnv (Join-Path $Root 'config.env')
Assert-ConfigKeys $Config @(
    'PI_IP', 'PROXY_PORT', 'REAL_USER', 'REAL_PASS', 'WHITELIST_IPS',
    'MEDIUM', 'HIGH', 'CRITICAL'
)
$Python = Get-VenvPython $Root
$MosquittoSub = Get-RequiredExecutable 'mosquitto_sub.exe'
$AttackIp = '127.0.0.2'
$Simulator = $null
$BackupDirectory = Join-Path $Root 'run\smoke-backup'
$DatabaseFiles = @('honeypot.db', 'honeypot.db-wal', 'honeypot.db-shm')
$RelayFile = Join-Path $Root 'sim\relay_state.txt'
$RelayBackup = Join-Path $BackupDirectory 'relay_state.txt'
$Started = $false

function Invoke-ExternalChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Invoke-MosquittoSub {
    param([Parameter(Mandatory = $true)][string]$OutputPath)

    $arguments = @(
        '-h', $Config.PI_IP, '-p', $Config.PROXY_PORT,
        '-u', $Config.REAL_USER, '-P', $Config.REAL_PASS,
        '-t', 'home/door/motion', '-C', '1'
    )
    $errorPath = "$OutputPath.err"
    $process = Start-Process -FilePath $MosquittoSub -ArgumentList (Join-NativeArguments $arguments) `
        -WorkingDirectory $Root -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $OutputPath -RedirectStandardError $errorPath
    if (-not $process.WaitForExit(12000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "Timed out waiting for legitimate MQTT traffic; inspect $errorPath"
    }
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "mosquitto_sub produced no output; inspect $errorPath"
    }
    $value = (Get-Content -Raw -LiteralPath $OutputPath).Trim()
    if ($value -notmatch '^[01]$') {
        throw "Expected a motion payload of 0 or 1, received '$value'."
    }
}

function Wait-RelayLocked {
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Test-Path -LiteralPath $RelayFile) -and
            ((Get-Content -Raw -LiteralPath $RelayFile).Trim() -eq 'LOCKED')) {
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'Simulator did not report a LOCKED relay within 10 seconds.'
}

if ($Config.PI_IP -ne '127.0.0.1') {
    throw 'Set PI_IP=127.0.0.1 in config.env for the native Windows smoke test.'
}
$whitelist = @($Config.WHITELIST_IPS.Split(',') | ForEach-Object { $_.Trim() })
if ($whitelist -notcontains '127.0.0.1') {
    throw 'WHITELIST_IPS must include 127.0.0.1 so the simulator remains legitimate.'
}
if ($whitelist -contains $AttackIp) {
    throw "$AttackIp must not be in WHITELIST_IPS for the smoke test."
}

Invoke-ExternalChecked $Python @(
    '-c', "import socket; s=socket.socket(); s.bind(('$AttackIp', 0)); s.close()"
)

& (Join-Path $Root 'windows\stop_all.ps1') | Out-Null
if (Test-Path -LiteralPath $BackupDirectory) {
    throw "Smoke-test backup directory already exists: $BackupDirectory. Recover or remove it before rerunning; it may contain data from an interrupted test."
}
New-Item -ItemType Directory -Force -Path $BackupDirectory | Out-Null
foreach ($name in $DatabaseFiles) {
    $source = Join-Path $Root "data\$name"
    $destination = Join-Path $BackupDirectory $name
    if (Test-Path -LiteralPath $source) { Move-Item -LiteralPath $source -Destination $destination }
}
if (Test-Path -LiteralPath $RelayFile) { Move-Item -LiteralPath $RelayFile -Destination $RelayBackup }

try {
    & (Join-Path $Root 'windows\run_all.ps1')
    $Started = $true

    $Simulator = Start-Process -FilePath $Python `
        -ArgumentList (Join-NativeArguments @((Join-Path $Root 'sim\sim_esp32.py'))) `
        -WorkingDirectory $Root -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Root 'logs\simulator.out.log') `
        -RedirectStandardError (Join-Path $Root 'logs\simulator.err.log')
    Wait-RelayLocked

    Write-Output 'Checking legitimate client on the real broker...'
    Invoke-MosquittoSub (Join-Path $Root 'logs\legitimate-before.txt')

    Write-Output 'Running suspicious traffic from isolated loopback source 127.0.0.2...'
    Invoke-ExternalChecked $Python @(
        (Join-Path $Root 'attacker\attack.py'), '--source-ip', $AttackIp
    )
    Start-Sleep -Seconds 1

    $databasePath = Join-Path $Root 'data\honeypot.db'
    if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
        throw 'SQLite audit database was not created.'
    }
    $attacker = Invoke-RestMethod -Uri "http://127.0.0.1:$($Config.DASH_PORT)/api/attacker/$AttackIp"
    $actions = @($attacker.timeline | ForEach-Object { $_.action } | Select-Object -Unique)
    $maximum = [double]$attacker.highest_risk
    $eventCount = @($attacker.timeline).Count
    $realSessions = @($attacker.sessions | Where-Object { $_.backend -eq 'real' }).Count
    $decoySessions = @($attacker.sessions | Where-Object { $_.backend -eq 'decoy' }).Count
    $unlocks = @($attacker.decoy_messages | Where-Object {
        $_.topic -eq 'home/door/lock' -and $_.payload -eq 'unlock'
    }).Count
    if ($maximum -lt [double]$Config.CRITICAL) {
        throw "Attacker maximum score $maximum did not reach CRITICAL $($Config.CRITICAL)."
    }
    foreach ($action in @('throttle', 'restrict', 'decoy')) {
        if ($actions -notcontains $action) {
            throw "Audit events did not record the expected '$action' action."
        }
    }
    if ($eventCount -lt 1 -or $realSessions -lt 1) {
        throw 'Expected SQLite event, attacker, and real-session audit records were not created.'
    }
    if ($decoySessions -lt 1 -or $unlocks -lt 1) {
        throw 'Suspicious client did not reach the decoy and record its unlock attempt.'
    }
    Wait-RelayLocked

    Write-Output 'Checking legitimate client remains functional after redirection...'
    Invoke-MosquittoSub (Join-Path $Root 'logs\legitimate-after.txt')
    Wait-RelayLocked
    Write-Output "PASS: actions include throttle/restrict/decoy; max score=$maximum; SQLite audit records=$eventCount"
    Write-Output "PASS: decoy sessions=$decoySessions, decoy unlocks=$unlocks, legitimate client functional, relay stayed LOCKED"
} finally {
    if ($Simulator) {
        $liveSimulator = Get-Process -Id $Simulator.Id -ErrorAction SilentlyContinue
        if ($liveSimulator) { Stop-Process -Id $Simulator.Id -Force -ErrorAction SilentlyContinue }
    }
    if ($Started -or (Test-Path -LiteralPath (Join-Path $Root 'run\windows-processes.json'))) {
        & (Join-Path $Root 'windows\stop_all.ps1') | Out-Null
    }
    foreach ($name in $DatabaseFiles) {
        $testFile = Join-Path $Root "data\$name"
        if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
        $backup = Join-Path $BackupDirectory $name
        if (Test-Path -LiteralPath $backup) { Move-Item -LiteralPath $backup -Destination $testFile }
    }
    if (Test-Path -LiteralPath $RelayFile) { Remove-Item -LiteralPath $RelayFile -Force }
    if (Test-Path -LiteralPath $RelayBackup) { Move-Item -LiteralPath $RelayBackup -Destination $RelayFile }
    if (Test-Path -LiteralPath $BackupDirectory) { Remove-Item -LiteralPath $BackupDirectory -Force }
}
