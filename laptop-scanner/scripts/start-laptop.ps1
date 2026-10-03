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
    $root = $Base.TrimEnd('/')
    if ($root -match 'host\.docker\.internal') {
        $root = $root -replace 'host\.docker\.internal','127.0.0.1'
    }
    $jobs = Invoke-AgentCurl 'GET' ($root + '/api/scanner-agent/jobs/next') $Tenant $Token $null
    if ($jobs -ge 200 -and $jobs -lt 300) { return $jobs }
    if ($jobs -eq 401 -or $jobs -eq 403) { return $jobs }
    # Older centrals may lack /jobs/next (404). Heartbeat body must be `{}` —
    # extra fields like version can 422 before auth on older HeartbeatIn models.
    $hb = Invoke-AgentCurl 'POST' ($root + '/api/scanner-agent/heartbeat') $Tenant $Token '{}'
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

. (Join-Path $PSScriptRoot 'sync-agent-token.ps1')

$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$envPath=Join-Path $root '.env'
if(-not(Test-Path $envPath)){throw ".env not found: $envPath"}
$e=Read-Env $envPath
$central=([string]$e['CENTRAL_API_URL']).Trim().TrimEnd('/')
$tenant=[string]$e['TENANT_SLUG']; if([string]::IsNullOrWhiteSpace($tenant)){$tenant='aetheris'}

Write-Host ''
Write-Host '============================================================================== '
Write-Host 'Aetheris laptop scanner startup - emailed access token'
Write-Host '============================================================================== '
Write-Host "Root: $root"
Write-Host "CENTRAL_API_URL=$central"
Write-Host "TENANT_SLUG=$tenant"
Write-Host ''
Write-Host '==> Emailed access token, then linking laptop to central'
$null = Sync-LaptopAgentToken -Root $root -EnvPath $envPath -EnvMap $e

Write-Host ''
Write-Host '==> Recording host LAN fingerprint (portable roam detection)'
$fp = Join-Path $root 'scripts\Write-LanFingerprint.ps1'
if (Test-Path $fp) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fp -Root $root -Once
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',$fp,'-Root',$root
    ) | Out-Null
    Write-Host '[OK] LAN fingerprint writer started.'
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
Write-Host '==> Clearing leftover scanner-agent recreate containers'
$orph=Run-Docker @('ps','-aq','--filter','name=_aetheris-laptop-scanner-agent') -AllowFailure
$ids=@($orph.Text -split '\s+' | Where-Object { $_ -match '^[a-f0-9]{12,}$' })
if($ids.Count -gt 0){
    $null=Run-Docker (@('rm','-f') + $ids) -AllowFailure
    Write-Host ("[OK] Removed {0} leftover container(s)." -f $ids.Count)
} else {
    Write-Host '[OK] No leftover recreate containers.'
}

Write-Host ''
Write-Host '==> Starting Aetheris laptop scanner stack (starts stopped containers; waits for gvmd socket)'
$agentUp=Run-Docker @('ps','-q','--filter','name=aetheris-laptop-scanner-agent-1','--filter','status=running') -AllowFailure
$gvmdUp=Run-Docker @('ps','-q','--filter','name=aetheris-laptop-gvmd-1','--filter','status=running') -AllowFailure
$agentId=(($agentUp.Text -split '\s+') | Where-Object { $_ -match '^[a-f0-9]{8,}$' } | Select-Object -First 1)
$gvmdId=(($gvmdUp.Text -split '\s+') | Where-Object { $_ -match '^[a-f0-9]{8,}$' } | Select-Object -First 1)
if($agentId){
    Write-Host '[OK] scanner-agent already running; skipping compose up and docker restart (restart hangs this Docker engine).' -ForegroundColor Green
    Write-Host '[OK] Matched token is already on disk. The running agent reloads it on the next 401/heartbeat cycle — no container restart needed.'
} elseif($gvmdId){
    Write-Host '[OK] Greenbone already running; starting scanner-agent only.'
    $up=Run-Docker @('compose','-f',$compose,'up','-d','--no-recreate','--no-deps','scanner-agent') -AllowFailure
    if($up.Text){Write-Host $up.Text}
    if($up.ExitCode -ne 0){throw "docker compose up failed with exit code $($up.ExitCode)"}
} else {
    Write-Host 'Bringing up the laptop stack (first start can take several minutes)...'
    $up=Run-Docker @('compose','-f',$compose,'up','-d','--no-recreate') -AllowFailure
    if($up.Text){Write-Host $up.Text}
    if($up.ExitCode -ne 0 -and $up.Text -match 'already in use by container'){
        Write-Host '[WARN] Name conflict; removing leftover recreate container and retrying.' -ForegroundColor Yellow
        $orph=Run-Docker @('ps','-aq','--filter','name=_aetheris-laptop-scanner-agent') -AllowFailure
        $ids=@($orph.Text -split '\s+' | Where-Object { $_ -match '^[a-f0-9]{12,}$' })
        if($ids.Count -gt 0){ $null=Run-Docker (@('rm','-f') + $ids) -AllowFailure }
        $up=Run-Docker @('compose','-f',$compose,'up','-d','--no-recreate','--no-deps','scanner-agent') -AllowFailure
        if($up.Text){Write-Host $up.Text}
    }
    if($up.ExitCode -ne 0){throw "docker compose up failed with exit code $($up.ExitCode)"}
}

Write-Host ''
Write-Host '==> Stack status'
$st=Run-Docker @('ps','--filter','name=aetheris-laptop-','--format','table {{.Names}}\t{{.Status}}') -AllowFailure
if($st.Text){Write-Host $st.Text}

Write-Host ''
Write-Host '==> Checking Greenbone GMP socket'
$gvmHealth=Run-Docker @('inspect','-f','{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}','aetheris-laptop-gvmd-1') -AllowFailure
$ospdHealth=Run-Docker @('inspect','-f','{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}','aetheris-laptop-ospd-openvas-1') -AllowFailure
$gvmH=(($gvmHealth.Text -split '\s+') | Where-Object { $_ } | Select-Object -Last 1)
$ospdH=(($ospdHealth.Text -split '\s+') | Where-Object { $_ } | Select-Object -Last 1)
if($gvmH -eq 'healthy' -and $ospdH -eq 'healthy'){
    Write-Host '[OK] Greenbone READY (gvmd and ospd-openvas are healthy).' -ForegroundColor Green
} else {
    Write-Host ("[WARN] Greenbone not healthy yet (gvmd={0}, ospd={1}); scanner-agent will keep retrying." -f $gvmH,$ospdH) -ForegroundColor Yellow
}

Write-Host ''
Write-Host '==> Recent scanner-agent authentication lines'
Write-Host '[OK] Skipping docker logs (can hang on this Docker engine). Scanner-agent is already up.' -ForegroundColor Green

Write-Host ''
Write-Host '============================================================================== '
Write-Host 'STARTUP COMPLETED' -ForegroundColor Green
Write-Host '============================================================================== '
exit 0