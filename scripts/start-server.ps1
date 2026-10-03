# Start the full Aetheris premise / server stack in one go (Windows).
# Does NOT start the client-laptop scanner-agent.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-server.ps1
#   .\Start-Server.cmd
#
param(
    [switch]$IncludeWazuh,
    [switch]$NoBuild,
    [switch]$SkipHealthWait
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Resolve-Docker {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $fallback = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $fallback) {
        return $fallback
    }
    throw "Docker not found. Start Docker Desktop and ensure docker.exe is installed."
}

function Wait-HttpOk {
    param(
        [string]$Url,
        [int]$TimeoutSec = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $ok = $false
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) {
                $ok = $true
            }
        } catch {
            $ok = $false
        }
        if ($ok) {
            return $true
        }
        Start-Sleep -Seconds 3
    }
    return $false
}

Push-Location $root
$failed = $false
$failMsg = ""

try {
    Write-Host "Aetheris premise server startup" -ForegroundColor Green
    Write-Host "Root: $root"

    $docker = Resolve-Docker
    Write-Step "Checking Docker engine"
    & $docker info 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker engine is not running. Start Docker Desktop, wait until it is ready, then re-run."
    }
    Write-Host "Docker OK: $docker"

    if (-not (Test-Path (Join-Path $root ".env"))) {
        Write-Host "WARNING: .env missing - copy .env.example to .env before production use." -ForegroundColor Yellow
    }

    Write-Step "Starting three independent Aetheris products"
    $stackArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $root "scripts\start-stack.ps1"), "-Service", "all")
    if ($NoBuild) { $stackArgs += "-NoBuild" }
    if ($IncludeWazuh) { $stackArgs += "-IncludeWazuh" }
    $laptopGvm = @()
    try {
        $laptopGvm = @(& $docker ps --format "{{.Names}}" | Where-Object { $_ -match 'aetheris-laptop' })
    } catch {}
    if ($laptopGvm.Count -gt 0) {
        Write-Host "Laptop OpenVAS already running - not forcing -IncludeGvm on Service 3." -ForegroundColor Yellow
    } else {
        $stackArgs += "-IncludeGvm"
    }
    & powershell @stackArgs
    if ($LASTEXITCODE -ne 0) {
        throw "start-stack.ps1 failed (exit $LASTEXITCODE)"
    }

    if (-not $SkipHealthWait) {
        Write-Step "Waiting for product API health"
        foreach ($item in @(
            @{ Url = "http://127.0.0.1:8083/health"; Label = "Forensic" },
            @{ Url = "http://127.0.0.1:8081/health"; Label = "Mobile extraction" },
            @{ Url = "http://127.0.0.1:8082/health"; Label = "Vulnerabilities" }
        )) {
            if (Wait-HttpOk -Url $item.Url -TimeoutSec 240) {
                Write-Host "$($item.Label) healthy: $($item.Url)" -ForegroundColor Green
            } else {
                Write-Host "WARNING: $($item.Label) not ready yet - $($item.Url)" -ForegroundColor Yellow
            }
        }
    }

    Write-Host ""
    Write-Host "Three independent products are up." -ForegroundColor Green
    Write-Host "  Forensic UI:          http://localhost:3001  API :8083"
    Write-Host "  Mobile extraction UI: http://localhost:3002  API :8081"
    Write-Host "  Vuln UI:              http://localhost:3003  API :8082"
    Write-Host "  Helper:               http://127.0.0.1:9876/health"
    Write-Host ""
    Write-Host "Laptop scanner-agent is NOT started here (point CENTRAL_API_URL at Service 3)." -ForegroundColor DarkGray
    Write-Host "Done."
} catch {
    $failed = $true
    $failMsg = $_.Exception.Message
} finally {
    Pop-Location
}

if ($failed) {
    Write-Host ""
    Write-Host "FAILED: $failMsg" -ForegroundColor Red
    exit 1
}

exit 0
