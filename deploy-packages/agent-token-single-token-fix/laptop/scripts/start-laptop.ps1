[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Read-Env([string]$Path) {
    $map = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*#') { continue }
        $i = $line.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $line.Substring(0,$i).Trim(); $v = $line.Substring($i+1).Trim()
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) { if ($v.Length -ge 2) { $v=$v.Substring(1,$v.Length-2) } }
        $map[$k]=$v
    }
    return $map
}
function Invoke-AgentCurl([string]$Method,[string]$Url,[string]$Tenant,[string]$Token,[string]$Body) {
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { return -1 }
    $outFile = [IO.Path]::GetTempFileName()
    try {
        # Windows PowerShell Invoke-WebRequest strips Authorization; curl.exe does not.
        if ($Method -eq 'GET') {
            $code = & curl.exe -sS -o $outFile -w '%{http_code}' -X GET $Url `
                -H "Authorization: Bearer $Token" `
                -H "X-Tenant: $Tenant" `
                --connect-timeout 15 --max-time 30 2>$null
        } else {
            $code = & curl.exe -sS -o $outFile -w '%{http_code}' -X POST $Url `
                -H "Authorization: Bearer $Token" `
                -H "X-Tenant: $Tenant" `
                -H 'Content-Type: application/json' `
                --data-raw $Body `
                --connect-timeout 15 --max-time 30 2>$null
        }
        if ($LASTEXITCODE -ne 0) { return -1 }
        return [int]$code
    } catch {
        return -1
    } finally {
        Remove-Item -Force $outFile -ErrorAction SilentlyContinue
    }
}
function Test-Cred([string]$Base,[string]$Tenant,[string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Token) -or $Token -eq 'replace-me') { return 0 }
    $rootUrl = $Base.TrimEnd('/')
    if ($rootUrl -match 'host\.docker\.internal') {
        $rootUrl = $rootUrl -replace 'host\.docker\.internal','127.0.0.1'
    }
    $jobs = Invoke-AgentCurl 'GET' ($rootUrl + '/api/scanner-agent/jobs/next') $Tenant $Token $null
    if ($jobs -ge 200 -and $jobs -lt 300) { return $jobs }
    if ($jobs -eq 401 -or $jobs -eq 403) { return $jobs }
    # Older centrals may lack /jobs/next (404). Heartbeat body must be `{}` —
    # extra fields like version can 422 before auth on older HeartbeatIn models.
    $hb = Invoke-AgentCurl 'POST' ($rootUrl + '/api/scanner-agent/heartbeat') $Tenant $Token '{}'
    if ($hb -ne -1 -and $hb -ne 0) { return $hb }
    return $jobs
}
function Explain-AuthStatus([int]$Code, [string]$Label) {
    switch ($Code) {
        0   { return "$Label missing/empty in .env (or still replace-me)" }
        200 { return "$Label accepted" }
        201 { return "$Label accepted" }
        401 { return "$Label rejected by central (invalid/rotated/revoked, or wrong TENANT_SLUG)" }
        403 { return "$Label firm suspended (HTTP 403)" }
        404 { return "$Label tenant not found - TENANT_SLUG must match the org you log into at CENTRAL_API_URL (HTTP 404)" }
        422 { return "$Label central rejected the probe payload (HTTP 422); update start-laptop.ps1 or retry" }
        -1  { return "$Label network/TLS failure reaching CENTRAL_API_URL" }
        default { return "$Label unexpected HTTP $Code" }
    }
}
function Run-Docker([string[]]$A,[switch]$AllowFailure) {
    $old=$ErrorActionPreference
    try { $ErrorActionPreference='Continue'; $o=& docker.exe @A 2>&1; $c=$LASTEXITCODE } finally { $ErrorActionPreference=$old }
    $t=(@($o|ForEach-Object{$_.ToString()})-join [Environment]::NewLine)
    if(-not $AllowFailure -and $c -ne 0){throw "docker command failed ($c): docker $($A -join ' ')`n$t"}
    [pscustomobject]@{ExitCode=$c;Text=$t}
}

$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$envPath=Join-Path $root '.env'
if(-not(Test-Path $envPath)){throw ".env not found: $envPath"}
$e=Read-Env $envPath
$central=([string]$e['CENTRAL_API_URL']).Trim().TrimEnd('/')
$tenant=[string]$e['TENANT_SLUG']; if([string]::IsNullOrWhiteSpace($tenant)){$tenant='aetheris'}
$current=[string]$e['AGENT_TOKEN']

Write-Host ''
Write-Host '============================================================================== '
Write-Host 'Aetheris laptop scanner startup - single AGENT_TOKEN'
Write-Host '============================================================================== '
Write-Host "Root: $root"
Write-Host "CENTRAL_API_URL=$central"
Write-Host "TENANT_SLUG=$tenant"
Write-Host ''
Write-Host '==> Checking agent credentials'
$s1=Test-Cred $central $tenant $current
if($s1 -ge 200 -and $s1 -lt 300){
    Write-Host "[OK] AGENT_TOKEN accepted (HTTP $s1)." -ForegroundColor Green
} else {
    Write-Host ("[ERROR] {0}" -f (Explain-AuthStatus $s1 'AGENT_TOKEN')) -ForegroundColor Red
    Write-Host ''
    Write-Host 'Use a single AGENT_TOKEN from the same UI as CENTRAL_API_URL:' -ForegroundColor Yellow
    Write-Host '  1) Confirm TENANT_SLUG matches the firm you log into there'
    Write-Host '  2) Vuln -> Scanners -> key icon to reissue AGENT_TOKEN (shown once)'
    Write-Host '  3) Set only AGENT_TOKEN in this laptop .env (leave AGENT_RECOVERY_TOKEN empty)'
    Write-Host '  4) Re-run Start-Laptop.cmd'
    Write-Host ''
    throw "AGENT_TOKEN was not accepted by central. status=$s1"
}

Write-Host ''
Write-Host '==> Checking Docker Desktop Linux engine'
$info=Run-Docker @('info') -AllowFailure
if($info.ExitCode -ne 0){
    $null=Run-Docker @('desktop','start','--timeout','120') -AllowFailure
    Start-Sleep -Seconds 5
    $info=Run-Docker @('info') -AllowFailure
}
if($info.ExitCode -ne 0){throw "Docker engine is not ready.`n$($info.Text)"}
Write-Host '[OK] Docker engine is ready.' -ForegroundColor Green

$compose=$null
foreach($n in @('docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml')){ $p=Join-Path $root $n; if(Test-Path $p){$compose=$p;break} }
if(-not $compose){throw 'Docker Compose file not found.'}

Write-Host ''
Write-Host '==> Starting Aetheris laptop scanner stack (starts stopped containers; waits for gvmd socket)'
$up=Run-Docker @('compose','-f',$compose,'up','-d') -AllowFailure
if($up.Text){Write-Host $up.Text}
if($up.ExitCode -ne 0){throw "docker compose up failed with exit code $($up.ExitCode)"}

Write-Host ''
$ps=Run-Docker @('compose','-f',$compose,'ps') -AllowFailure
if($ps.Text){Write-Host $ps.Text}

Write-Host ''
Write-Host '==> Waiting for Greenbone GMP socket (gvmd can take several minutes after start)'
$readyOk=$false
for($i=1; $i -le 24; $i++){
    $ready=Run-Docker @('compose','-f',$compose,'exec','-T','scanner-agent','python','/app/check_greenbone_ready.py') -AllowFailure
    if($ready.ExitCode -eq 0){
        if($ready.Text){Write-Host $ready.Text}
        Write-Host '[OK] Greenbone READY.' -ForegroundColor Green
        $readyOk=$true
        break
    }
    Write-Host ("[WAIT] Greenbone not ready yet ({0}/24): {1}" -f $i, (($ready.Text -split "`n")[0]))
    Start-Sleep -Seconds 15
}
if(-not $readyOk){
    if($ready.Text){Write-Host $ready.Text}
    Write-Host '[WARN] Greenbone is not ready yet; scanner-agent will keep retrying and will not claim jobs until GMP is up.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '==> Recent scanner-agent authentication lines'
$logs=Run-Docker @('compose','-f',$compose,'logs','--tail','60','scanner-agent') -AllowFailure
if($logs.Text){
    $sel=@($logs.Text -split "`r?`n" | Where-Object {$_ -match 'heartbeat|401 Unauthorized|200 OK|durable recovery|auth_recovery|not claiming new jobs|Greenbone'})
    if($sel.Count -gt 0){$sel|ForEach-Object{Write-Host $_}}else{Write-Host $logs.Text}
}

Write-Host ''
Write-Host '============================================================================== '
Write-Host 'STARTUP COMPLETED' -ForegroundColor Green
Write-Host '============================================================================== '
exit 0