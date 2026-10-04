# Build and start the Aetheris stacks on localhost.
#
#   .\start_docke_local.ps1
#       Build with the Docker layer cache, then start forensic, Android,
#       iOS, vulnerabilities (Greenbone, ZAP, Trivy), and the local gateway.
#
#   .\start_docke_local.ps1 cache
#   .\start_docke_local.ps1 -Cache
#   .\start_docke_local.ps1 -NoCache
#       Same start, but images are rebuilt with --no-cache.
param(
    [Alias("Cache")]
    [switch]$NoCache,
    [Parameter(Position = 0)]
    [string]$Mode = ""
)

$ErrorActionPreference = "Stop"
# Docker writes progress to stderr. That must not abort the script on PowerShell 7.
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if ($Mode -match '^(?i)(cache|nocache|no-cache)$') {
    $NoCache = $true
}

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Docker {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string[]]$DockerArgs
    )
    Write-Host $Title
    & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$Title failed (exit $LASTEXITCODE)"
    }
}

function Test-RunningContainers {
    $projects = @(
        "aetheris-forensic",
        "aetheris-mobile-android",
        "aetheris-mobile-ios",
        "aetheris-vuln",
        "aetheris-gateway"
    )
    $oneShot = 'ollama-init|configure-openvas|pg-gvm-migrator|gpg-data|acme-bootstrap|certbot'
    $failed = @()
    $running = 0
    $present = @{}
    foreach ($project in $projects) {
        $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=$project")
        $present[$project] = $ids.Count
        foreach ($id in $ids) {
            $id = "$id".Trim()
            if (-not $id) { continue }
            $name = (& docker inspect --format "{{.Name}}" $id).TrimStart("/")
            $status = & docker inspect --format "{{.State.Status}}" $id
            $health = & docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" $id
            $exitCode = & docker inspect --format "{{.State.ExitCode}}" $id
            $isOneShot = $name -match $oneShot
            if ($status -eq "running" -and ($health -eq "healthy" -or $health -eq "none" -or $health -eq "starting")) {
                $running++
                continue
            }
            if ($isOneShot -and $status -eq "exited" -and "$exitCode" -eq "0") {
                continue
            }
            $failed += "$name status=$status health=$health exit=$exitCode"
        }
    }
    $missing = @($projects | Where-Object { -not $present[$_] })
    return @{ Running = $running; Failed = @($failed); Missing = @($missing) }
}

$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    throw "Docker was not found. Start Docker Desktop, then run this script again."
}
& docker info --format "{{.ServerVersion}}" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker is installed but the engine is not running. Start Docker Desktop, then run this script again."
}

$buildFlag = @()
if ($NoCache) {
    $buildFlag = @("--no-cache")
    Write-Host "Build mode: no cache" -ForegroundColor Yellow
} else {
    Write-Host "Build mode: use Docker layer cache" -ForegroundColor Green
}

Write-Step "Build forensic API image"
Invoke-Docker -Title "forensic api" -DockerArgs (@(
    "compose", "-f", "services/forensic/docker-compose.yml",
    "--project-directory", $root, "--project-name", "aetheris-forensic",
    "build"
) + $buildFlag + @("api"))

Write-Step "Build Android app image"
Invoke-Docker -Title "android" -DockerArgs (@(
    "compose", "-f", "services/mobile-android/docker-compose.yml",
    "--project-directory", $root, "--project-name", "aetheris-mobile-android",
    "build"
) + $buildFlag + @("api", "frontend"))

Write-Step "Build iOS app image"
Invoke-Docker -Title "ios" -DockerArgs (@(
    "compose", "-f", "services/mobile-ios/docker-compose.yml",
    "--project-directory", $root, "--project-name", "aetheris-mobile-ios",
    "build"
) + $buildFlag + @("api", "frontend"))

Write-Step "Build vulnerability API and scanner worker"
Invoke-Docker -Title "vulnerability scanner" -DockerArgs (@(
    "compose", "-f", "services/vuln/docker-compose.yml",
    "--project-directory", $root, "--project-name", "aetheris-vuln",
    "--profile", "vuln-scanners", "--profile", "gvm",
    "build"
) + $buildFlag + @("api", "worker-nessus"))

Write-Step "Build localhost gateway"
Invoke-Docker -Title "gateway" -DockerArgs (@(
    "compose", "--project-directory", $root, "--project-name", "aetheris-gateway",
    "-f", "services/gateway/docker-compose.yml",
    "build"
) + $buildFlag + @("gateway"))

Write-Step "Start forensic, Android, iOS, vulnerability, and gateway"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\start-stack.ps1") -Service all -NoBuild
if ($LASTEXITCODE -ne 0) {
    throw "start-stack failed (exit $LASTEXITCODE)"
}

Write-Step "Check that every localhost stack is up"
$deadline = (Get-Date).AddMinutes(3)
$report = $null
do {
    $report = Test-RunningContainers
    if ($report.Failed.Count -eq 0 -and $report.Missing.Count -eq 0) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

if ($report.Missing.Count -gt 0) {
    Write-Host "These Compose projects have no containers:" -ForegroundColor Red
    $report.Missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw "Missing stacks: $($report.Missing -join ', ')"
}
if ($report.Failed.Count -gt 0) {
    Write-Host "These containers are not up:" -ForegroundColor Red
    $report.Failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw "Container check failed ($($report.Failed.Count) not up, $($report.Running) running)."
}
Write-Host "$($report.Running) containers are running." -ForegroundColor Green

Write-Host ""
Write-Host "Aetheris is up on localhost." -ForegroundColor Green
Write-Host "  UI:       http://localhost:3000/   (alias http://localhost:3001/)"
Write-Host "  Forensic: http://127.0.0.1:8083/health"
Write-Host "  Android:  http://localhost:3002/   API http://127.0.0.1:8081/health"
Write-Host "  iOS:      http://localhost:3004/   API http://127.0.0.1:8084/health"
Write-Host "  Vuln:     API http://127.0.0.1:8082/health"
exit 0
