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
if (-not (Test-Path -LiteralPath $Python)) {
    py -3.11 -m venv (Join-Path $Root '.venv')
}
& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $Root 'requirements.txt')

foreach ($command in @('mosquitto', 'mosquitto_passwd')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command is not on PATH. Install Mosquitto for Windows and reopen PowerShell."
    }
}
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'data'), (Join-Path $Root 'logs'), (Join-Path $Root 'run') | Out-Null
$PasswordFile = Join-Path $Root 'data\real.passwd'
& mosquitto_passwd -b -c $PasswordFile $Config.REAL_USER $Config.REAL_PASS
Write-Output 'Windows setup complete. Next: .\pi\run_all.ps1'
