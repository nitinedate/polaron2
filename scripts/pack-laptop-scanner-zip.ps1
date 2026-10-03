# Build deployable zip: dist/Aetheris-Laptop-Scanner.zip
# Contents: Start-Laptop.cmd + OpenVAS/agent compose + scanner-agent sources + .env.example
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pack-laptop-scanner-zip.ps1

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$pkg = Join-Path $repo "laptop-scanner"
$agentSrc = Join-Path $repo "scanner-agent"
$agentDst = Join-Path $pkg "scanner-agent"
$dist = Join-Path $repo "dist"
$stamp = Get-Date -Format "yyyyMMdd"
$zipName = "Aetheris-Laptop-Scanner-$stamp.zip"
$zipPath = Join-Path $dist $zipName
$latestPath = Join-Path $dist "Aetheris-Laptop-Scanner.zip"

function Write-Step([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Cyan
}

if (-not (Test-Path $pkg)) {
    throw "Missing package folder: $pkg"
}
if (-not (Test-Path (Join-Path $agentSrc "Dockerfile"))) {
    throw "Missing scanner-agent at $agentSrc"
}

Write-Step "Syncing scanner-agent into laptop-scanner"
if (Test-Path $agentDst) {
    Remove-Item $agentDst -Recurse -Force
}
New-Item -ItemType Directory -Path $agentDst | Out-Null
Copy-Item (Join-Path $agentSrc "Dockerfile") $agentDst
Copy-Item (Join-Path $agentSrc "requirements.txt") $agentDst
Copy-Item (Join-Path $agentSrc "agent") (Join-Path $agentDst "agent") -Recurse

# Never ship secrets
$envFile = Join-Path $pkg ".env"
if (Test-Path $envFile) {
    Write-Host "Note: excluding laptop-scanner\.env from zip (secrets)."
}

Write-Step "Creating staging folder"
$stage = Join-Path $env:TEMP ("aetheris-laptop-pack-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stage | Out-Null
$stageRoot = Join-Path $stage "Aetheris-Laptop-Scanner"
New-Item -ItemType Directory -Path $stageRoot | Out-Null

$include = @(
    "Start-Laptop.cmd",
    "docker-compose.yml",
    ".env.example",
    "README.md",
    "scripts",
    "scanner-agent"
)
foreach ($name in $include) {
    $srcPath = Join-Path $pkg $name
    if (-not (Test-Path $srcPath)) {
        throw "Missing required package file: $srcPath"
    }
    $destPath = Join-Path $stageRoot $name
    if ((Get-Item $srcPath).PSIsContainer) {
        Copy-Item $srcPath $destPath -Recurse
    } else {
        Copy-Item $srcPath $destPath
    }
}

# Drop any accidental .env under stage
Get-ChildItem -Path $stageRoot -Filter ".env" -Recurse -Force -ErrorAction SilentlyContinue |
    Remove-Item -Force

if (-not (Test-Path $dist)) {
    New-Item -ItemType Directory -Path $dist | Out-Null
}
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
if (Test-Path $latestPath) { Remove-Item $latestPath -Force }

Write-Step "Compressing $zipName"
Compress-Archive -Path $stageRoot -DestinationPath $zipPath -Force
Copy-Item $zipPath $latestPath -Force

Remove-Item $stage -Recurse -Force

Write-Host ""
Write-Host "Created:" -ForegroundColor Green
Write-Host "  $zipPath"
Write-Host "  $latestPath"
Write-Host ""
Write-Host "Copy the zip to the client laptop, extract, edit .env, run Start-Laptop.cmd"
