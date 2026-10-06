param()
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Config = @{}
Get-Content -LiteralPath (Join-Path $Root 'config.env') | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
        $key, $value = $line.Split('=', 2)
        $Config[$key.Trim()] = $value.Trim().Trim('"').Trim("'")
    }
}
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run .\pi\setup_windows.ps1 first.' }
& (Join-Path $PSScriptRoot 'stop_all.ps1') | Out-Null
$Logs = Join-Path $Root 'logs'; $Run = Join-Path $Root 'run'; $Data = Join-Path $Root 'data'
New-Item -ItemType Directory -Force -Path $Logs, $Run, $Data | Out-Null
$PasswordFile = Join-Path $Data 'real.passwd'
if (-not (Test-Path -LiteralPath $PasswordFile)) {
    & mosquitto_passwd -b -c $PasswordFile $Config.REAL_USER $Config.REAL_PASS
}
$real = (Get-Content -Raw -LiteralPath (Join-Path $Root 'pi\mosquitto\real.conf')).Replace('@REAL_PORT@', $Config.REAL_PORT).Replace('@PASSWORD_FILE@', $PasswordFile.Replace('\', '/'))
$decoy = (Get-Content -Raw -LiteralPath (Join-Path $Root 'pi\mosquitto\decoy.conf')).Replace('@DECOY_PORT@', $Config.DECOY_PORT)
Set-Content -LiteralPath (Join-Path $Run 'real.conf') -Value $real -Encoding utf8
Set-Content -LiteralPath (Join-Path $Run 'decoy.conf') -Value $decoy -Encoding utf8

function Start-ManagedProcess([string]$Name, [string]$FilePath, [string[]]$Arguments) {
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Logs "$Name.out.log") -RedirectStandardError (Join-Path $Logs "$Name.err.log")
    Set-Content -LiteralPath (Join-Path $Run "$Name.pid") -Value $process.Id -Encoding ascii
    Start-Sleep -Milliseconds 500
    if ($process.HasExited) { throw "$Name failed to start; inspect logs\$Name.err.log" }
}

Start-ManagedProcess 'real-broker' 'mosquitto' @('-c', (Join-Path $Run 'real.conf'))
Start-ManagedProcess 'decoy-broker' 'mosquitto' @('-c', (Join-Path $Run 'decoy.conf'))
Start-ManagedProcess 'decoy-publisher' $Python @((Join-Path $Root 'pi\decoy\decoy_publisher.py'))
Start-ManagedProcess 'proxy' $Python @((Join-Path $Root 'pi\proxy\proxy.py'))
Start-ManagedProcess 'dashboard' $Python @((Join-Path $Root 'pi\dashboard\app.py'))
Write-Output "Stack started: MQTT proxy $($Config.PI_IP):$($Config.PROXY_PORT); dashboard http://$($Config.PI_IP):$($Config.DASH_PORT)"
