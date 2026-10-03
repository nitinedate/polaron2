# Build and start the Aetheris Docker stacks, then publish HTTPS on 80/443.
#
#   .\docker_start.ps1
#       Build with the Docker layer cache, start every product, attach the
#       public HTTPS gateway, and verify containers are up.
#
#   .\docker_start.ps1 -Cache
#   .\docker_start.ps1 -NoCache
#   .\docker_start.ps1 cache
#       Same start, but images are rebuilt with --no-cache.
#
# The gateway listens on 80 and 443 for the site name (APP_BASE_URL) and for
# the static address https://122.179.141.248/. An existing Let's Encrypt
# certificate is reused for the domain. The static IP uses its own certificate
# so the browser name matches that address.
param(
    [Alias("Cache")]
    [switch]$NoCache,
    [Parameter(Position = 0)]
    [string]$Mode = "",
    [string]$Domain = "",
    [string]$PublicIP = "122.179.141.248"
)

$ErrorActionPreference = "Stop"
# Docker writes progress to stderr. That must not abort the script on PowerShell 7.
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
. (Join-Path $root "scripts\free-published-ports.ps1")

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

function Get-SiteDomain {
    if ($Domain) { return $Domain.Trim().TrimEnd('.') }
    $envFile = Join-Path $root ".env"
    if (Test-Path -LiteralPath $envFile) {
        foreach ($line in @(Get-Content -LiteralPath $envFile)) {
            if ($line -match '^\s*APP_BASE_URL\s*=\s*https?://([^/\s]+)') {
                return $Matches[1].Trim().TrimEnd('.')
            }
        }
    }
    return "future-softtech.co.in"
}

function Get-HostIps {
    $found = New-Object System.Collections.Generic.List[string]
    $found.Add("127.0.0.1") | Out-Null
    if ($PublicIP) { $found.Add($PublicIP.Trim()) | Out-Null }
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -and
                $_.IPAddress -notlike "127.*" -and
                $_.IPAddress -notlike "169.254.*"
            } |
            ForEach-Object { $found.Add($_.IPAddress) | Out-Null }
    } catch { }
    return @($found | Sort-Object -Unique)
}

function New-LocalCertificate {
    param(
        [string]$CertName,
        [string[]]$DnsNames,
        [string[]]$Ips
    )
    $san = @()
    foreach ($name in @($DnsNames | Where-Object { $_ } | Sort-Object -Unique)) {
        $san += "DNS:$name"
    }
    foreach ($ip in @($Ips | Where-Object { $_ } | Sort-Object -Unique)) {
        $san += "IP:$ip"
    }
    $sanText = ($san -join ",")
    $shell = "apk add --no-cache openssl >/dev/null && mkdir -p /etc/letsencrypt/live/$CertName && openssl req -x509 -nodes -newkey rsa:2048 -days 825 -keyout /etc/letsencrypt/live/$CertName/privkey.pem -out /etc/letsencrypt/live/$CertName/fullchain.pem -subj /CN=$CertName -addext subjectAltName=$sanText"
    & docker run --rm -v aetheris-gateway_certbot_etc:/etc/letsencrypt nginx:1.27-alpine sh -c $shell
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the HTTPS certificate for $CertName"
    }
}

function Test-CertificateFile {
    param([string]$CertName)
    & docker run --rm -v aetheris-gateway_certbot_etc:/etc/letsencrypt:ro nginx:1.27-alpine sh -c "test -f '/etc/letsencrypt/live/$CertName/fullchain.pem'"
    return ($LASTEXITCODE -eq 0)
}

function Ensure-HttpsCertificate {
    param([string]$SiteDomain, [string]$StaticIP, [string[]]$Ips)
    if (Test-CertificateFile -CertName $SiteDomain) {
        Write-Host "Using the existing HTTPS certificate for $SiteDomain."
    } else {
        Write-Host "No certificate for $SiteDomain. Creating a local HTTPS certificate."
        New-LocalCertificate -CertName $SiteDomain -DnsNames @($SiteDomain, "localhost") -Ips $Ips
        Write-Host "Local certificate covers $SiteDomain. Browsers will warn until a trusted certificate replaces it."
    }

    if (Test-CertificateFile -CertName $StaticIP) {
        Write-Host "Using the existing HTTPS certificate for $StaticIP."
        return
    }
    Write-Host "No certificate for $StaticIP. Creating a local HTTPS certificate so https://$StaticIP/ matches this address."
    $ipSans = @($Ips + @($StaticIP, "127.0.0.1"))
    New-LocalCertificate -CertName $StaticIP -DnsNames @($SiteDomain, "localhost") -Ips $ipSans
    Write-Host "https://$StaticIP/ is ready. Browsers will warn until a trusted certificate replaces this local one."
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
    foreach ($project in $projects) {
        $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=$project")
        foreach ($id in $ids) {
            $id = "$id".Trim()
            if (-not $id) { continue }
            $name = (& docker inspect --format "{{.Name}}" $id).TrimStart("/")
            $status = & docker inspect --format "{{.State.Status}}" $id
            $health = & docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" $id
            $exitCode = & docker inspect --format "{{.State.ExitCode}}" $id
            $isOneShot = $name -match $oneShot
            if ($status -eq "running" -and ($health -eq "healthy" -or $health -eq "none")) {
                $running++
                continue
            }
            if ($isOneShot -and $status -eq "exited" -and "$exitCode" -eq "0") {
                continue
            }
            $failed += "$name status=$status health=$health exit=$exitCode"
        }
    }
    return @{ Running = $running; Failed = @($failed) }
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

Write-Step "Build vulnerability scanner worker"
Invoke-Docker -Title "vulnerability scanner worker" -DockerArgs (@(
    "compose", "-f", "services/vuln/docker-compose.yml",
    "--project-directory", $root, "--project-name", "aetheris-vuln",
    "--profile", "vuln-scanners", "--profile", "gvm",
    "build"
) + $buildFlag + @("worker-nessus"))

if (-not $PublicIP) { $PublicIP = "122.179.141.248" }
$siteDomain = Get-SiteDomain
$hostIps = @(Get-HostIps)
Write-Step "HTTPS certificates for $siteDomain and $PublicIP"
Ensure-HttpsCertificate -SiteDomain $siteDomain -StaticIP $PublicIP -Ips $hostIps

Write-Step "Build gateway UI"
Invoke-Docker -Title "gateway" -DockerArgs (@(
    "compose", "--project-directory", $root, "--project-name", "aetheris-gateway",
    "-f", "services/gateway/docker-compose.yml",
    "-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml",
    "build"
) + $buildFlag + @("gateway"))

Write-Step "Start forensic, Android, iOS, and vulnerability stacks"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\start-stack.ps1") -Service all -NoBuild
if ($LASTEXITCODE -ne 0) {
    throw "start-stack failed (exit $LASTEXITCODE)"
}

Write-Step "Publish HTTPS on ports 80, 443, and 3001"
$gatewayCompose = @(
    "compose", "--project-directory", $root, "--project-name", "aetheris-gateway",
    "-f", "services/gateway/docker-compose.yml",
    "-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml"
)
Clear-OccupiedHostPorts -Docker (Get-Command docker).Source -ComposeArgs $gatewayCompose -Services @("gateway") -IncludeRunning
Invoke-Docker -Title "gateway https" -DockerArgs @($gatewayCompose + @(
    "up", "-d", "--force-recreate", "--wait", "--wait-timeout", "180", "gateway"
))

Write-Step "Check that every container is up"
$deadline = (Get-Date).AddMinutes(3)
$report = $null
do {
    $report = Test-RunningContainers
    if ($report.Failed.Count -eq 0) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

if ($report.Failed.Count -gt 0) {
    Write-Host "These containers are not up:" -ForegroundColor Red
    $report.Failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw "Container check failed ($($report.Failed.Count) not up, $($report.Running) running)."
}
Write-Host "$($report.Running) containers are running." -ForegroundColor Green

$httpsCode = & curl.exe -sk -o NUL -w "%{http_code}" --max-redirs 0 "https://127.0.0.1/"
if ("$httpsCode" -ne "200") {
    throw "HTTPS gateway did not return 200 on https://127.0.0.1/ (got $httpsCode)"
}

Write-Host ""
Write-Host "Aetheris is up." -ForegroundColor Green
Write-Host "  Website:   https://$siteDomain/"
Write-Host "  Static IP: https://$PublicIP/"
foreach ($ip in @($hostIps)) {
    if ($ip -eq $PublicIP) { continue }
    Write-Host "  By IP:     https://$ip/"
}
Write-Host "  Local UI: http://localhost:3001/  (redirects to HTTPS)"
Write-Host "  Android:  http://localhost:3002/"
Write-Host "  iOS:      http://localhost:3004/"
exit 0
