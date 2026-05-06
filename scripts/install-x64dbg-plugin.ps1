param(
    [Parameter(Mandatory = $true)]
    [string]$X64DbgPluginsDir,

    [string]$PluginBinary = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")

if (-not $PluginBinary) {
    $PluginBinary = Join-Path $RepoRoot "dist\x64dbg\ix64mcp.dp64"
}

if (-not (Test-Path $PluginBinary)) {
    throw "x64dbg plugin binary not found: $PluginBinary. Download ix64mcp.dp64 from GitHub Releases or build it with scripts\build-x64dbg-plugin.ps1."
}

New-Item -ItemType Directory -Force -Path $X64DbgPluginsDir | Out-Null
$Destination = Join-Path $X64DbgPluginsDir "ix64mcp.dp64"
Copy-Item -LiteralPath $PluginBinary -Destination $Destination -Force

Write-Host "[IX64MCP] Installed x64dbg bridge: $Destination"
