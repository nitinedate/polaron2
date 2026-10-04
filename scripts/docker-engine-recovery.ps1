# V45.3 - Docker Desktop (WSL2) recovery for stuck containers.
#
# Symptom (production, during `docker compose up -d` recreate):
#   Error response from daemon: cannot stop container: <id>: tried to kill container,
#   but did not receive an exit event
#
# Meaning: SIGKILL was delivered but a process in the container is in an
# uninterruptible kernel state (blocked on the Windows bind-mount file-sharing
# layer or inside an NVIDIA/CUDA call). No docker command can end it; only the
# docker-desktop VM restart can. This module:
#   1. stops workers with the configured grace period BEFORE recreate (so Celery
#      cold-shutdown can release GPU/locks and exit on its own);
#   2. on the daemon error, tries `docker rm -f`; if that fails,
#   3. restarts the Docker Desktop engine (`wsl --shutdown` + relaunch) and waits
#      for `docker info` - gated by -AutoRecoverEngine so an operator can opt out.
# Dot-source from start-stack.ps1.

function Test-StuckContainerError {
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match "did not receive an exit event") -or
           ($Text -match "cannot stop container") -or
           ($Text -match "cannot kill container") -or
           ($Text -match "is not running or is not killable")
}

function Get-StuckContainerIds {
    param([string]$Text)
    $ids = @()
    foreach ($m in [regex]::Matches(($Text | Out-String), "container[: ]+([0-9a-f]{12,64})")) {
        $ids += $m.Groups[1].Value
    }
    return @($ids | Select-Object -Unique)
}

function Stop-AetherisWorkers {
    param(
        [string]$Docker,
        [string[]]$ComposeArgs,
        [string[]]$Services,
        [int]$GraceSec = 120
    )
    if (-not $Services.Count) { return $true }
    Write-Host "Stopping [$($Services -join ', ')] with ${GraceSec}s grace (Celery cold shutdown)..."
    $out = & $Docker @ComposeArgs stop -t $GraceSec @Services 2>&1
    $out | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -eq 0) { return $true }
    return -not (Test-StuckContainerError ($out | Out-String))
}

function Remove-StuckContainers {
    param([string]$Docker, [string[]]$Ids)
    $ok = $true
    foreach ($id in $Ids) {
        Write-Host "Force-removing stuck container $id ..." -ForegroundColor Yellow
        $out = & $Docker rm -f $id 2>&1
        $out | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0 -and (Test-StuckContainerError ($out | Out-String))) { $ok = $false }
    }
    return $ok
}

function Wait-DockerEngine {
    param([string]$Docker, [int]$TimeoutSec = 420)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        & $Docker info 1>$null 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Seconds 5
    }
    return $false
}

function Restart-DockerDesktopEngine {
    param([string]$Docker)
    Write-Host ""
    Write-Host "Restarting the Docker Desktop engine to clear an unkillable container (docker-desktop VM restart)..." -ForegroundColor Yellow
    $exe = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    try { Get-Process "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    try { Get-Process "com.docker.backend" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 3
    try { & wsl --shutdown 2>&1 | ForEach-Object { Write-Host "  wsl: $_" } } catch {}
    Start-Sleep -Seconds 5
    if (-not $exe) {
        Write-Host "Docker Desktop.exe not found - start Docker Desktop manually, then re-run." -ForegroundColor Red
        return $false
    }
    Start-Process -FilePath $exe | Out-Null
    Write-Host "Waiting for the engine (up to 7 minutes)..."
    if (-not (Wait-DockerEngine -Docker $Docker -TimeoutSec 420)) {
        Write-Host "Docker engine did not come back." -ForegroundColor Red
        return $false
    }
    Write-Host "Docker engine is back." -ForegroundColor Green
    return $true
}

function Invoke-ComposeWithRecovery {
    <#
      Runs `docker compose <args>`; on the stuck-container daemon error, performs
      rm -f -> engine restart (if $AutoRecoverEngine) -> one retry.
      Returns $true on success.
    #>
    param(
        [string]$Docker,
        [string[]]$ComposeArgs,
        [string[]]$ComposeCommand,
        [switch]$AutoRecoverEngine
    )
    $out = & $Docker @ComposeArgs @ComposeCommand 2>&1
    $out | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -eq 0) { return $true }
    $text = ($out | Out-String)
    if (-not (Test-StuckContainerError $text)) { return $false }

    Write-Host ""
    Write-Host "Docker could not stop a container (process in uninterruptible I/O or CUDA call)." -ForegroundColor Yellow
    $ids = Get-StuckContainerIds $text
    if ($ids.Count -and (Remove-StuckContainers -Docker $Docker -Ids $ids)) {
        Write-Host "Stuck container removed; retrying compose..."
    }
    elseif ($AutoRecoverEngine) {
        if (-not (Restart-DockerDesktopEngine -Docker $Docker)) { return $false }
    }
    else {
        Write-Host "Run again with -AutoRecoverEngine (or restart Docker Desktop manually: wsl --shutdown) and retry." -ForegroundColor Red
        return $false
    }
    $out = & $Docker @ComposeArgs @ComposeCommand 2>&1
    $out | ForEach-Object { Write-Host $_ }
    return ($LASTEXITCODE -eq 0)
}
