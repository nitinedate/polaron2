# Shared starter for script_docker\start_docker_*.cmd
#
#   start_docker_local.cmd
#       Build with the Docker layer cache and start every product on localhost.
#
#   start_docker_local.cmd cache
#       Same start, but images are rebuilt with --no-cache.
#
#   start_docker_nitin.cmd [cache]
#       Build, configure nginx, create SSL certificates, and publish
#       https://122.179.140.167 and https://future-softtech.co.in
#
#   start_docker_prod.cmd [cache]
#       Build, configure nginx, create the SSL certificate, and publish
#       https://122.179.141.248
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("local", "nitin", "prod")]
    [string]$Profile,
    [Alias("Cache")]
    [switch]$NoCache,
    [Parameter(Position = 0)]
    [string]$Mode = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
. (Join-Path $root "scripts\free-published-ports.ps1")

if ($Mode -match '^(?i)(cache|nocache|no-cache)$') {
    $NoCache = $true
}

$public = switch ($Profile) {
    "nitin" {
        @{
            Ip = "122.179.140.167"
            Domain = "future-softtech.co.in"
        }
    }
    "prod" {
        @{
            Ip = "122.179.141.248"
            Domain = ""
        }
    }
    default { $null }
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

function Get-HostIps {
    param([string]$PublicIP)
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

function Test-CertificateFile {
    param([string]$CertName)
    & docker run --rm -v aetheris-gateway_certbot_etc:/etc/letsencrypt:ro nginx:1.27-alpine sh -c "test -f '/etc/letsencrypt/live/$CertName/fullchain.pem' && test -f '/etc/letsencrypt/live/$CertName/privkey.pem'"
    return ($LASTEXITCODE -eq 0)
}

function New-SslCertificate {
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
    if (-not $san.Count) { throw "Certificate $CertName has no subject alternative names." }
    $sanText = ($san -join ",")
    $shell = "apk add --no-cache openssl >/dev/null && mkdir -p /etc/letsencrypt/live/$CertName && openssl req -x509 -nodes -newkey rsa:2048 -days 825 -keyout /etc/letsencrypt/live/$CertName/privkey.pem -out /etc/letsencrypt/live/$CertName/fullchain.pem -subj /CN=$CertName -addext subjectAltName=$sanText && ls -la /etc/letsencrypt/live/$CertName"
    & docker run --rm -v aetheris-gateway_certbot_etc:/etc/letsencrypt nginx:1.27-alpine sh -c $shell
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the HTTPS certificate for $CertName"
    }
}

function Ensure-PublicCertificateVolume {
    foreach ($name in @("aetheris-gateway_certbot_etc", "aetheris-gateway_certbot_www")) {
        & docker volume inspect $name 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) {
            & docker volume create $name | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not create Docker volume $name" }
        }
    }
}

function Test-PublicNginxConfig {
    $httpsConf = (Join-Path $root "deployment\windows-ip-https\nginx.gateway.https.conf") -replace '\\', '/'
    $locations = (Join-Path $root "deployment\windows-ip-https\gateway-https-locations.inc") -replace '\\', '/'
    $proxy = (Join-Path $root "frontend\gateway-proxy.inc") -replace '\\', '/'
    & docker run --rm `
        -v "${httpsConf}:/etc/nginx/conf.d/default.conf:ro" `
        -v "${locations}:/etc/nginx/conf.d/gateway-https-locations.inc:ro" `
        -v "${proxy}:/etc/nginx/conf.d/gateway-proxy.inc:ro" `
        -v "aetheris-gateway_certbot_etc:/etc/letsencrypt:ro" `
        nginx:1.27-alpine nginx -t
    if ($LASTEXITCODE -ne 0) {
        throw "Nginx rejected the public HTTPS configuration."
    }
    Write-Host "Nginx configuration is valid."
}

function Ensure-SslCertificate {
    param(
        [string]$CertName,
        [string[]]$DnsNames,
        [string[]]$Ips
    )
    if (Test-CertificateFile -CertName $CertName) {
        Write-Host "Using the existing HTTPS certificate for $CertName."
        return
    }
    Write-Host "Creating HTTPS certificate for $CertName."
    New-SslCertificate -CertName $CertName -DnsNames $DnsNames -Ips $Ips
    Write-Host "Certificate ready: $CertName"
}

function Get-TlsServerBlock {
    param(
        [string]$ServerName,
        [string]$CertName,
        [switch]$DefaultServer
    )
    $listen = if ($DefaultServer) {
        "listen 443 ssl default_server;`r`n    listen [::]:443 ssl default_server;"
    } else {
        "listen 443 ssl;`r`n    listen [::]:443 ssl;"
    }
    return @"
server {
    $listen
    server_name $ServerName;

    ssl_certificate     /etc/letsencrypt/live/$CertName/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$CertName/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_prefer_server_ciphers off;

    root /usr/share/nginx/html;
    index index.html;
    server_tokens off;
    client_max_body_size 0;
    error_log /dev/stderr warn;

    include /etc/nginx/conf.d/gateway-https-locations.inc;
}
"@
}

function Write-PublicNginxConfig {
    param(
        [string]$PublicIP,
        [string]$Domain
    )
    $names = @($PublicIP)
    if ($Domain) { $names = @($Domain) + $names }
    $httpNames = (($names + @("_")) -join " ")
    $blocks = @()
    if ($Domain) {
        $blocks += Get-TlsServerBlock -ServerName $Domain -CertName $Domain
    }
    $blocks += Get-TlsServerBlock -ServerName "$PublicIP _" -CertName $PublicIP -DefaultServer
    $text = @"
# Public HTTPS edge for aetheris-gateway.
# Written by script_docker\start_docker.ps1 for this host.
resolver 127.0.0.11 valid=10s ipv6=off;

map `$http_x_aetheris_service `$hdr_upstream {
    default                         http://host.docker.internal:8083;
    forensic                        http://host.docker.internal:8083;
    mobile-android                  http://host.docker.internal:8081;
    android                         http://host.docker.internal:8081;
    mobile-ios                      http://host.docker.internal:8084;
    ios                             http://host.docker.internal:8084;
    mobile-extract                  http://host.docker.internal:8081;
    mobile                          http://host.docker.internal:8081;
    vuln                            http://host.docker.internal:8082;
}

server {
    listen 80;
    listen [::]:80;
    server_name $httpNames;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
        try_files `$uri =404;
    }

    location / {
        return 301 https://`$host`$request_uri;
    }
}

$($blocks -join "`r`n")
"@
    $path = Join-Path $root "deployment\windows-ip-https\nginx.gateway.https.conf"
    [System.IO.File]::WriteAllText($path, $text.Replace("`n", "`r`n").Replace("`r`r`n", "`r`n"), [System.Text.UTF8Encoding]::new($false))
    Write-Host "Nginx HTTPS config written for $httpNames"
}

function Enable-PublicFirewall {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Not running as Administrator. Open TCP 80 and 443 in Windows Firewall so the internet can reach this host." -ForegroundColor Yellow
        return
    }
    foreach ($port in @(80, 443)) {
        $name = "Aetheris HTTPS TCP $port"
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($existing) {
            $existing | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any | Out-Null
        } else {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
        }
        Write-Host "Firewall allows TCP $port."
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
    $pending = 0
    $running = 0
    $present = @{}
    foreach ($project in $projects) {
        $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=$project")
        $present[$project] = @($ids | Where-Object { "$_".Trim() }).Count
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
            if ($status -eq "running" -and $health -eq "starting") {
                $pending++
                continue
            }
            if ($isOneShot -and $status -eq "exited" -and "$exitCode" -eq "0") {
                continue
            }
            $failed += "$name status=$status health=$health exit=$exitCode"
        }
    }
    $missing = @($projects | Where-Object { -not $present[$_] })
    return @{ Running = $running; Pending = $pending; Failed = @($failed); Missing = @($missing) }
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
Write-Host "Profile: $Profile"

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

$gatewayFiles = @(
    "compose", "--project-directory", $root, "--project-name", "aetheris-gateway",
    "-f", "services/gateway/docker-compose.yml"
)
if ($public) {
    $gatewayFiles += @("-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml")
    $hostIps = @(Get-HostIps -PublicIP $public.Ip)
    Write-Step "Nginx and HTTPS certificates"
    Enable-PublicFirewall
    Ensure-PublicCertificateVolume
    if ($public.Domain) {
        Ensure-SslCertificate -CertName $public.Domain -DnsNames @($public.Domain, "localhost") -Ips $hostIps
    }
    Ensure-SslCertificate -CertName $public.Ip -DnsNames @($public.Domain, "localhost") -Ips @($hostIps + @($public.Ip, "127.0.0.1"))
    Write-PublicNginxConfig -PublicIP $public.Ip -Domain $public.Domain
    Test-PublicNginxConfig
}

Write-Step "Build gateway"
Invoke-Docker -Title "gateway" -DockerArgs ($gatewayFiles + @("build") + $buildFlag + @("gateway"))

Write-Step "Start forensic, Android, iOS, vulnerability, and gateway"
$stackArgs = @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $root "scripts\start-stack.ps1"),
    "-Service", "all", "-NoBuild",
    # V45.3: production must never be left half-recreated by an unkillable worker.
    "-AutoRecoverEngine"
)
# Production and the public host publish 80/443. Do not also bind 0.0.0.0:3000
# here — that port is already taken on the production machine, and the HTTPS
# gateway started below does not use it.
if ($public) { $stackArgs += "-SkipGateway" }
& powershell @stackArgs
if ($LASTEXITCODE -ne 0) {
    throw "start-stack failed (exit $LASTEXITCODE)"
}

if ($public) {
    Write-Step "Start nginx on ports 80 and 443 for internet HTTPS"
    Clear-OccupiedHostPorts -Docker (Get-Command docker).Source -ComposeArgs $gatewayFiles -Services @("gateway") -IncludeRunning
    Invoke-Docker -Title "gateway https" -DockerArgs ($gatewayFiles + @(
        "up", "-d", "--force-recreate", "--wait", "--wait-timeout", "180", "gateway"
    ))
    & docker exec aetheris-gateway-gateway-1 nginx -t
    if ($LASTEXITCODE -ne 0) {
        throw "The running nginx gateway did not accept the HTTPS configuration."
    }
}

Write-Step "Check that every stack is up"
$deadline = (Get-Date).AddMinutes(3)
$report = $null
do {
    $report = Test-RunningContainers
    if ($report.Failed.Count -eq 0 -and $report.Missing.Count -eq 0 -and $report.Pending -eq 0) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

if ($report.Missing.Count -gt 0) {
    Write-Host "These Compose projects have no containers:" -ForegroundColor Red
    $report.Missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw "Missing stacks: $($report.Missing -join ', ')"
}
if ($report.Failed.Count -gt 0 -or $report.Pending -gt 0) {
    Write-Host "These containers are not up:" -ForegroundColor Red
    $report.Failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    if ($report.Pending -gt 0) { Write-Host "  $($report.Pending) container(s) still starting." -ForegroundColor Red }
    throw "Container check failed ($($report.Failed.Count) not up, $($report.Pending) starting, $($report.Running) running)."
}
Write-Host "$($report.Running) containers are running." -ForegroundColor Green

if ($public) {
    $httpsCode = & curl.exe -sk -o NUL -w "%{http_code}" --max-redirs 0 "https://127.0.0.1/"
    if ("$httpsCode" -ne "200") {
        throw "HTTPS gateway did not return 200 on https://127.0.0.1/ (got $httpsCode)"
    }
    if ($public.Domain) {
        $domainCode = & curl.exe -sk -o NUL -w "%{http_code}" --max-redirs 0 --resolve "$($public.Domain):443:127.0.0.1" "https://$($public.Domain)/"
        if ("$domainCode" -ne "200") {
            throw "HTTPS gateway did not return 200 for https://$($public.Domain)/ (got $domainCode)"
        }
    }
}

Write-Host ""
Write-Host "Aetheris is up ($Profile)." -ForegroundColor Green
if (-not $public) {
    Write-Host "  UI:       http://localhost:3000/   (alias http://localhost:3001/)"
    Write-Host "  Forensic: http://127.0.0.1:8083/health"
    Write-Host "  Android:  http://localhost:3002/"
    Write-Host "  iOS:      http://localhost:3004/"
    Write-Host "  Vuln:     http://127.0.0.1:8082/health"
} else {
    Write-Host "  Internet: https://$($public.Ip)/"
    if ($public.Domain) { Write-Host "  Internet: https://$($public.Domain)/" }
    Write-Host "  Local UI: http://localhost:3001/"
    Write-Host "  Android:  http://localhost:3002/"
    Write-Host "  iOS:      http://localhost:3004/"
    Write-Host "Forward TCP 80 and 443 from the public address to this PC."
}
exit 0
