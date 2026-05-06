param(
    [Parameter(Mandatory = $true)]
    [string]$IdaPluginsDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$Source = Join-Path $RepoRoot "bridges\ida\ix64mcp_ida.py"

if (-not (Test-Path $Source)) {
    throw "IDA bridge source not found: $Source"
}

New-Item -ItemType Directory -Force -Path $IdaPluginsDir | Out-Null
$Destination = Join-Path $IdaPluginsDir "ix64mcp_ida.py"
Copy-Item -LiteralPath $Source -Destination $Destination -Force

Write-Host "[IX64MCP] Installed IDA bridge: $Destination"
