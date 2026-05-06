param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw ".venv was not found. Run scripts\install.ps1 first."
}

Push-Location $RepoRoot
try {
    & $Python -m ix64mcp.server doctor
}
finally {
    Pop-Location
}
