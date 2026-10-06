[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

$Root = Get-RepositoryRoot
$Config = Import-ConfigEnv (Join-Path $Root 'config.env')
Assert-ConfigKeys $Config @('REAL_USER', 'REAL_PASS', 'REAL_PORT', 'DECOY_PORT')

function Test-Python311 {
    param([string]$Executable, [string[]]$PrefixArguments = @())
    try {
        $version = & $Executable @PrefixArguments -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}"); raise SystemExit(sys.version_info < (3, 11))' 2>$null
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{ Executable = $Executable; Prefix = $PrefixArguments; Version = $version }
        }
    } catch {}
    return $null
}

$launcher = $null
$py = Get-Command 'py.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($py) { $launcher = Test-Python311 $py.Source @('-3') }
if (-not $launcher) {
    $pythonCommand = Get-Command 'python.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($pythonCommand) { $launcher = Test-Python311 $pythonCommand.Source }
}
if (-not $launcher) {
    throw 'Python 3.11 or newer was not found. Install 64-bit Python for Windows (including the py launcher or PATH option) and retry.'
}
Write-Output "Using Python $($launcher.Version): $($launcher.Executable)"

$venvPython = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    Write-Output 'Creating .venv...'
    & $launcher.Executable @($launcher.Prefix) -m venv (Join-Path $Root '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python failed to create .venv.' }
}

& $venvPython -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'
if ($LASTEXITCODE -ne 0) {
    throw 'The existing .venv uses Python older than 3.11. Remove .venv and rerun setup.ps1.'
}
& $venvPython -m pip --version
if ($LASTEXITCODE -ne 0) { throw 'pip is unavailable in .venv.' }
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'Failed to upgrade pip.' }
& $venvPython -m pip install -r (Join-Path $Root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Failed to install requirements.txt.' }

$directories = @('data', 'logs', 'run') | ForEach-Object { Join-Path $Root $_ }
New-Item -ItemType Directory -Force -Path $directories | Out-Null

$mosquitto = Get-RequiredExecutable 'mosquitto.exe'
$passwordTool = Get-RequiredExecutable 'mosquitto_passwd.exe'
$null = Get-RequiredExecutable 'mosquitto_sub.exe'

# The Windows installer commonly starts a system broker on 1883. The project
# owns that port while running, matching setup_pi.sh's systemd behavior.
$mosquittoService = Get-Service -Name 'mosquitto' -ErrorAction SilentlyContinue
if ($mosquittoService) {
    try {
        if ($mosquittoService.Status -ne 'Stopped') {
            Stop-Service -Name 'mosquitto' -Force -ErrorAction Stop
            $mosquittoService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
        }
        Set-Service -Name 'mosquitto' -StartupType Disabled -ErrorAction Stop
        Write-Output 'Disabled the system Mosquitto service; this repository starts its own two broker processes.'
    } catch {
        throw "The Mosquitto Windows service must be stopped and disabled because it occupies the proxy port. Rerun setup.ps1 from an elevated PowerShell. $($_.Exception.Message)"
    }
}

$passwordFile = Join-Path $Root 'data\real.passwd'
& $passwordTool -b -c $passwordFile $Config.REAL_USER $Config.REAL_PASS
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $passwordFile -PathType Leaf)) {
    throw 'mosquitto_passwd failed to create data\real.passwd.'
}
Protect-PasswordFile $passwordFile
Write-BrokerConfigs $Root $Config

Write-Output "Mosquitto: $mosquitto"
Write-Output 'Windows setup complete. Next: .\windows\run_all.ps1'
