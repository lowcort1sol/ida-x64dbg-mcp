param(
    [string]$BuildDir = "build\x64dbg-release",
    [string]$Generator = "Ninja",
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$SourceDir = Join-Path $RepoRoot "bridges\x64dbg"
$BuildPath = Join-Path $RepoRoot $BuildDir

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "x64dbg plugins are Windows-only."
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw "cmake was not found in PATH. Install CMake or run from a Visual Studio developer environment."
}

if (-not (Test-Path (Join-Path $RepoRoot "pluginsdk\x64dbg.lib"))) {
    throw "pluginsdk\x64dbg.lib not found. Ensure the x64dbg plugin SDK is present in pluginsdk/."
}

Push-Location $RepoRoot
try {
    Write-Host "[IX64MCP] Configuring x64dbg plugin"
    cmake -S $SourceDir -B $BuildPath -G $Generator -DCMAKE_BUILD_TYPE=$Configuration

    Write-Host "[IX64MCP] Building x64dbg plugin"
    cmake --build $BuildPath --config $Configuration

    Write-Host "[IX64MCP] Output: dist\x64dbg\ix64mcp.dp64"
}
finally {
    Pop-Location
}
