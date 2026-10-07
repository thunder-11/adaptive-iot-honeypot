Set-StrictMode -Version Latest

function Get-RepositoryRoot {
    return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
}

function Import-ConfigEnv {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Configuration file not found: $Path"
    }
    $values = @{}
    foreach ($rawLine in [System.IO.File]::ReadAllLines($Path)) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#') -or -not $line.Contains('=')) {
            continue
        }
        $key, $value = $line.Split('=', 2)
        $key = $key.Trim()
        $value = $value.Trim()
        if ($value.Length -ge 2) {
            $first = $value[0]
            $last = $value[$value.Length - 1]
            if (($first -eq '"' -and $last -eq '"') -or
                ($first -eq "'" -and $last -eq "'")) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }
        $values[$key] = $value
    }
    # Match pi.config.load_config: explicit process-environment values are
    # supported for CI/Docker and override keys already defined in config.env.
    foreach ($key in @($values.Keys)) {
        $override = [Environment]::GetEnvironmentVariable($key, 'Process')
        if ($null -ne $override) { $values[$key] = $override }
    }
    return $values
}

function Assert-ConfigKeys {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][string[]]$Keys
    )
    foreach ($key in $Keys) {
        if (-not $Config.ContainsKey($key) -or [string]::IsNullOrWhiteSpace($Config[$key])) {
            throw "config.env is missing required value: $key"
        }
    }
}

function Get-RequiredExecutable {
    param([Parameter(Mandatory = $true)][string]$Name)

    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command) {
        return $command.Source
    }
    $fileName = if ($Name.EndsWith('.exe')) { $Name } else { "$Name.exe" }
    $candidates = @()
    if ($env:ProgramFiles) {
        $candidates += Join-Path $env:ProgramFiles "Mosquitto\$fileName"
    }
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($programFilesX86) {
        $candidates += Join-Path $programFilesX86 "Mosquitto\$fileName"
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }
    throw "Required executable '$Name' was not found. Install Mosquitto for Windows and add its install directory to PATH (the default C:\Program Files\Mosquitto is also detected)."
}

function Get-VenvPython {
    param([Parameter(Mandatory = $true)][string]$Root)

    $python = Join-Path $Root '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw "Virtual environment not found at $python. Run .\windows\setup.ps1 first."
    }
    return $python
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Write-BrokerConfigs {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][hashtable]$Config
    )

    Assert-ConfigKeys $Config @('REAL_PORT', 'DECOY_PORT', 'DECOY_BIND_IP')
    $run = Join-Path $Root 'run'
    $passwordFile = (Join-Path $Root 'data\real.passwd').Replace('\', '/')
    $realTemplate = Get-Content -Raw -LiteralPath (Join-Path $Root 'pi\mosquitto\real.conf')
    $decoyTemplate = Get-Content -Raw -LiteralPath (Join-Path $Root 'pi\mosquitto\decoy.conf')
    $real = $realTemplate.Replace('@REAL_PORT@', $Config.REAL_PORT).
        Replace('@PASSWORD_FILE@', $passwordFile)
    $decoy = $decoyTemplate.Replace('@DECOY_PORT@', $Config.DECOY_PORT).
        Replace('@DECOY_BIND_IP@', $Config.DECOY_BIND_IP)
    Write-Utf8NoBom (Join-Path $run 'real.conf') $real
    Write-Utf8NoBom (Join-Path $run 'decoy.conf') $decoy
}

function Protect-PasswordFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $icacls = Get-Command 'icacls.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $icacls) {
        Write-Warning 'icacls.exe was not found; the Mosquitto password file retains filesystem-default permissions.'
        return
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    # Grant the owner before removing inheritance, so a failed ACL operation
    # cannot make the generated file inaccessible.
    & $icacls.Source $Path '/grant:r' "${identity}:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not harden ACLs for $Path; filesystem-default permissions remain in effect."
        return
    }
    & $icacls.Source $Path '/inheritance:r' '/grant:r' `
        "${identity}:(F)" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not fully harden ACLs for $Path; verify its permissions manually."
    }
}

function Join-NativeArguments {
    param([string[]]$Arguments)

    $quoted = foreach ($argument in $Arguments) {
        if ($argument -notmatch '[\s"]') {
            $argument
        } else {
            $builder = [System.Text.StringBuilder]::new()
            [void]$builder.Append('"')
            $slashes = 0
            foreach ($character in $argument.ToCharArray()) {
                if ($character -eq '\') {
                    $slashes++
                } elseif ($character -eq '"') {
                    [void]$builder.Append(('\' * ($slashes * 2 + 1)))
                    [void]$builder.Append('"')
                    $slashes = 0
                } else {
                    if ($slashes) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
                    [void]$builder.Append($character)
                }
            }
            if ($slashes) { [void]$builder.Append(('\' * ($slashes * 2))) }
            [void]$builder.Append('"')
            $builder.ToString()
        }
    }
    return $quoted -join ' '
}

function Wait-TcpPort {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSeconds = 10,
        [System.Diagnostics.Process]$Process,
        [string]$Name = 'process'
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process) {
            $Process.Refresh()
            if ($Process.HasExited) {
                throw "$Name exited before TCP port $Port became ready"
            }
        }
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync('127.0.0.1', $Port)
            if ($task.Wait(250) -and $client.Connected) {
                return
            }
        } catch {
            # The service may still be starting.
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 150
    }
    throw "$Name did not listen on TCP port $Port within $TimeoutSeconds seconds"
}

function Assert-TcpPortAvailable {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Parse($Address), $Port
    )
    $listener.Server.ExclusiveAddressUse = $true
    try {
        $listener.Start()
    } catch {
        throw "Cannot start ${Name}: TCP $Address`:$Port is already in use. Stop the owning service/process; if this is the Mosquitto Windows service, rerun .\windows\setup.ps1 from an elevated PowerShell."
    } finally {
        try { $listener.Stop() } catch {}
    }
}
