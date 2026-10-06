[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

$Root = Get-RepositoryRoot
$Config = Import-ConfigEnv (Join-Path $Root 'config.env')
Assert-ConfigKeys $Config @('PI_IP', 'PROXY_PORT', 'REAL_PORT', 'DECOY_PORT', 'DASH_PORT', 'REAL_USER', 'REAL_PASS')
$Python = Get-VenvPython $Root
$Mosquitto = Get-RequiredExecutable 'mosquitto.exe'
$PasswordTool = Get-RequiredExecutable 'mosquitto_passwd.exe'
$Logs = Join-Path $Root 'logs'
$Run = Join-Path $Root 'run'
$Data = Join-Path $Root 'data'
$StatePath = Join-Path $Run 'windows-processes.json'
New-Item -ItemType Directory -Force -Path $Logs, $Run, $Data | Out-Null

if (Test-Path -LiteralPath $StatePath) {
    & (Join-Path $PSScriptRoot 'stop_all.ps1') | Out-Null
}

$portValues = @(
    [int]$Config.PROXY_PORT, [int]$Config.REAL_PORT,
    [int]$Config.DECOY_PORT, [int]$Config.DASH_PORT
)
if (@($portValues | Select-Object -Unique).Count -ne $portValues.Count) {
    throw 'PROXY_PORT, REAL_PORT, DECOY_PORT, and DASH_PORT must be distinct in config.env.'
}
Assert-TcpPortAvailable '0.0.0.0' ([int]$Config.PROXY_PORT) 'inspection proxy'
Assert-TcpPortAvailable '127.0.0.1' ([int]$Config.REAL_PORT) 'real broker'
Assert-TcpPortAvailable '0.0.0.0' ([int]$Config.DECOY_PORT) 'decoy broker'
Assert-TcpPortAvailable '0.0.0.0' ([int]$Config.DASH_PORT) 'dashboard'

$PasswordFile = Join-Path $Data 'real.passwd'
if (-not (Test-Path -LiteralPath $PasswordFile -PathType Leaf)) {
    & $PasswordTool -b -c $PasswordFile $Config.REAL_USER $Config.REAL_PASS
    if ($LASTEXITCODE -ne 0) { throw 'mosquitto_passwd failed to create data\real.passwd.' }
    Protect-PasswordFile $PasswordFile
}
Write-BrokerConfigs $Root $Config

$script:ManagedProcesses = @()
function Save-ProcessState {
    $json = ConvertTo-Json -InputObject @($script:ManagedProcesses) -Depth 4
    Write-Utf8NoBom $StatePath $json
}

function Start-ManagedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$ReadyPort = 0
    )

    $outLog = Join-Path $Logs "$Name.out.log"
    $errLog = Join-Path $Logs "$Name.err.log"
    $process = Start-Process -FilePath $FilePath -ArgumentList (Join-NativeArguments $Arguments) `
        -WorkingDirectory $Root -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    $process.Refresh()
    $record = [pscustomobject]@{
        Name = $Name
        Id = $process.Id
        StartTimeUtc = $process.StartTime.ToUniversalTime().ToString('o')
        StartTimeUtcTicks = $process.StartTime.ToUniversalTime().Ticks
        ExecutablePath = [System.IO.Path]::GetFullPath($FilePath)
    }
    $script:ManagedProcesses += $record
    Set-Content -LiteralPath (Join-Path $Run "$Name.pid") -Value $process.Id -Encoding ascii
    Save-ProcessState

    Start-Sleep -Milliseconds 300
    $process.Refresh()
    if ($process.HasExited) {
        throw "$Name failed to start (exit code $($process.ExitCode)); inspect logs\$Name.err.log"
    }
    if ($ReadyPort -gt 0) {
        Wait-TcpPort -Port $ReadyPort -Process $process -Name $Name
    }
    return $process
}

try {
    $null = Start-ManagedProcess 'real-broker' $Mosquitto @('-c', (Join-Path $Run 'real.conf')) ([int]$Config.REAL_PORT)
    $null = Start-ManagedProcess 'decoy-broker' $Mosquitto @('-c', (Join-Path $Run 'decoy.conf')) ([int]$Config.DECOY_PORT)
    $null = Start-ManagedProcess 'decoy-publisher' $Python @((Join-Path $Root 'pi\decoy\decoy_publisher.py'))
    $null = Start-ManagedProcess 'proxy' $Python @((Join-Path $Root 'pi\proxy\proxy.py')) ([int]$Config.PROXY_PORT)
    $null = Start-ManagedProcess 'dashboard' $Python @((Join-Path $Root 'pi\dashboard\app.py')) ([int]$Config.DASH_PORT)
} catch {
    $message = $_.Exception.Message
    & (Join-Path $PSScriptRoot 'stop_all.ps1') | Out-Null
    throw "$message. Any components started by this run were stopped."
}

Write-Output "Stack started: MQTT proxy $($Config.PI_IP):$($Config.PROXY_PORT); dashboard http://$($Config.PI_IP):$($Config.DASH_PORT)"
Write-Output "Process state: $StatePath"
