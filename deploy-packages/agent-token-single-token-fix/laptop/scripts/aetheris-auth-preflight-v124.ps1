param([string]$Root=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
function V($p,$k){$m=Get-Content $p|?{$_ -match ('^'+[regex]::Escape($k)+'=(.*)$')}|select -Last 1;if($m -match ('^'+[regex]::Escape($k)+'=(.*)$')){$Matches[1].Trim()}}
function T($base,$tenant,$token){
  if(!$token){return $false}
  if(-not (Get-Command curl.exe -ErrorAction SilentlyContinue)){return $false}
  $url=($base.TrimEnd('/')+'/api/scanner-agent/jobs/next')
  $out=[IO.Path]::GetTempFileName()
  try{
    $code=& curl.exe -sS -o $out -w '%{http_code}' -X GET $url -H "Authorization: Bearer $token" -H "X-Tenant: $tenant" --connect-timeout 15 --max-time 30 2>$null
    if($LASTEXITCODE -ne 0){return $false}
    $n=[int]$code
    if($n -ge 200 -and $n -lt 300){return $true}
    if($n -eq 401 -or $n -eq 403){return $false}
    $hb=($base.TrimEnd('/')+'/api/scanner-agent/heartbeat')
    $code=& curl.exe -sS -o $out -w '%{http_code}' -X POST $hb -H "Authorization: Bearer $token" -H "X-Tenant: $tenant" -H 'Content-Type: application/json' --data-raw '{}' --connect-timeout 15 --max-time 30 2>$null
    if($LASTEXITCODE -ne 0){return $false}
    $n=[int]$code
    return ($n -ge 200 -and $n -lt 300)
  }finally{Remove-Item -Force $out -ErrorAction SilentlyContinue}
}
$e=Join-Path $Root '.env';$base=V $e 'CENTRAL_API_URL';if(!$base){$base='https://122.170.114.36'};$tenant=V $e 'TENANT_SLUG';if(!$tenant){$tenant='aetheris'}
if(T $base $tenant (V $e 'AGENT_TOKEN')){Write-Host '[OK] AGENT_TOKEN accepted.' -ForegroundColor Green;exit 0}
Write-Host '[ERROR] AGENT_TOKEN is not accepted by central. Set AGENT_TOKEN only (no recovery/rotate token).' -ForegroundColor Red;exit 1
