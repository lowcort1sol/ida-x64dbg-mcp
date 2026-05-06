param(
    [string]$IdaPluginsDir = "",
    [string]$X64DbgPluginsDir = "",
    [string]$X64DbgPluginBinary = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$VenvDir = Join-Path $RepoRoot ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

function Write-Step {
    param([string]$Message)
    Write-Host "[IX64MCP] $Message"
}

function Get-CommandPath {
    param([string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return $null
    }
    return $command.Source
}

function Get-PythonVersion {
    param([string]$PythonExe)
    $version = & $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    return [version]$version
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Find-CompatiblePython {
    $pyLauncher = Get-CommandPath "py"
    if ($pyLauncher) {
        try {
            & $pyLauncher -3.14 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,14) else 1)" | Out-Null
            return @($pyLauncher, "-3.14")
        }
        catch {
        }
    }

    $python = Get-CommandPath "python"
    if ($python) {
        try {
            if ((Get-PythonVersion $python) -ge [version]"3.14") {
                return @($python)
            }
        }
        catch {
        }
    }

    return $null
}

Push-Location $RepoRoot
try {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw "IX64MCP GitHub-alpha installer targets Windows only."
    }

    Write-Step "Repository: $RepoRoot"

    if (-not (Test-Path $VenvPython)) {
        $uv = Get-CommandPath "uv"
        if ($uv) {
            Write-Step "Creating .venv with uv and Python 3.14"
            Invoke-Native $uv "venv" "--python" "3.14" ".venv"
        }
        else {
            $pythonCommand = Find-CompatiblePython
            if ($null -eq $pythonCommand) {
                throw "Python 3.14+ or uv is required. Install Python 3.14+ or uv, then rerun scripts\install.ps1."
            }
            Write-Step "Creating .venv with $($pythonCommand -join ' ')"
            if ($pythonCommand.Length -gt 1) {
                Invoke-Native $pythonCommand[0] $pythonCommand[1] "-m" "venv" ".venv"
            }
            else {
                Invoke-Native $pythonCommand[0] "-m" "venv" ".venv"
            }
        }
    }
    else {
        Write-Step "Using existing .venv"
    }

    Write-Step "Installing IX64MCP package into .venv"
    Invoke-Native $VenvPython "-m" "ensurepip" "--upgrade"
    Invoke-Native $VenvPython "-m" "pip" "install" "--upgrade" "pip"
    Invoke-Native $VenvPython "-m" "pip" "install" "-e" "."

    New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "state") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "state\logs") | Out-Null

    if ($IdaPluginsDir) {
        & (Join-Path $ScriptDir "install-ida-plugin.ps1") -IdaPluginsDir $IdaPluginsDir
    }
    else {
        Write-Step "IDA plugin copy skipped. Pass -IdaPluginsDir to install it automatically."
    }

    if ($X64DbgPluginsDir) {
        & (Join-Path $ScriptDir "install-x64dbg-plugin.ps1") -X64DbgPluginsDir $X64DbgPluginsDir -PluginBinary $X64DbgPluginBinary
    }
    else {
        Write-Step "x64dbg plugin copy skipped. Pass -X64DbgPluginsDir and -X64DbgPluginBinary to install it automatically."
    }

    $escapedPython = $VenvPython.Replace("\", "\\")
    Write-Host ""
    Write-Host "Add this to your Codex MCP config:"
    Write-Host ""
    Write-Host "[mcp_servers.ix64mcp]"
    Write-Host "command = `"$escapedPython`""
    Write-Host "args = [`"-m`", `"ix64mcp.server`", `"mcp`"]"
    Write-Host ""
    Write-Step "Start daemon: .\.venv\Scripts\python -m ix64mcp.server start"
    Write-Step "Verify:       .\scripts\doctor.ps1"
}
finally {
    Pop-Location
}
