# Ensure the shared host CPU/GPU capacity Redis is listening on 127.0.0.1:6389.
# Product workers (forensic / mobile-extract / vuln) use
# RESOURCE_GOVERNOR_REDIS_URL=redis://host.docker.internal:6389/0 for fail-closed
# admission. Without this container, extract tasks retry forever with:
#   CpuHeavySlotTimeout('resource governor unavailable: ... 6389 ...')
#
# Usage (from repo root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\ensure-capacity.ps1

param(
    [int]$WaitTimeoutSec = 60
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Resolve-Docker {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $fallback = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $fallback) { return $fallback }
    throw "Docker not found."
}

$docker = Resolve-Docker
Write-Host "Ensuring shared capacity coordinator on 127.0.0.1:6389..." -ForegroundColor Cyan
& $docker compose --project-directory $root --project-name aetheris-capacity `
    -f services/capacity/docker-compose.yml up -d --wait --wait-timeout $WaitTimeoutSec
if ($LASTEXITCODE -ne 0) {
    throw "aetheris-capacity startup failed (exit $LASTEXITCODE)"
}
Write-Host "Capacity Redis healthy on 127.0.0.1:6389" -ForegroundColor Green
