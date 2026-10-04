# Move disk/mobile processing data out of the Docker Desktop WSL disk
# (F:\DockerDesktopWSL) and into a normal folder that can be relocated.
#
# Postgres stays in its Docker volume: a Windows folder cannot store Postgres
# data files reliably. MinIO objects, job files, Ollama models, and Hugging Face
# caches are the data that grows while a disk or phone is processed.
#
# To move the backup later:
#   1. Stop the stack
#   2. Move the folder (for example F:\PolaronBackup -> D:\PolaronBackup)
#   3. Change AETHERIS_BACKUP_DIR in .env
#   4. Start the stack again

$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Get-Docker {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        $dockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
        if (Test-Path $dockerExe) { return $dockerExe }
        return "docker"
    }
    return $docker.Source
}

function Read-EnvValue {
    param([string]$Name)
    $envFile = Join-Path $root ".env"
    if (-not (Test-Path -LiteralPath $envFile)) { return $null }
    foreach ($line in Get-Content -LiteralPath $envFile) {
        if ($line -match "^\s*$Name\s*=\s*(.*?)\s*$") {
            return $Matches[1].Trim().Trim('"').Trim("'")
        }
    }
    return $null
}

function Ensure-BackupEnv {
    param([string]$PathValue)
    $envFile = Join-Path $root ".env"
    $current = Read-EnvValue "AETHERIS_BACKUP_DIR"
    if ($current) { return $current }
    $forward = ($PathValue -replace '\\', '/')
    if (Test-Path -LiteralPath $envFile) {
        Add-Content -LiteralPath $envFile -Value "`r`n# Movable folder for disk/mobile processing data (outside DockerDesktopWSL).`r`nAETHERIS_BACKUP_DIR=$forward`r`n"
    }
    return $forward
}

function Test-Ready {
    param([string]$Dir)
    Test-Path -LiteralPath (Join-Path $Dir ".ready")
}

function Mark-Ready {
    param([string]$Dir)
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Set-Content -LiteralPath (Join-Path $Dir ".ready") -Value (Get-Date -Format o) -Encoding ascii
}

function Get-CopyImage {
    param([string]$Docker)
    $images = @(& $Docker images --format "{{.Repository}}:{{.Tag}}" 2>$null)
    foreach ($name in @("pgvector/pgvector:pg16", "alpine:latest", "alpine:3")) {
        if ($images -contains $name) { return $name }
    }
    $fallback = @($images | Where-Object { $_ -and $_ -ne "<none>:<none>" } | Select-Object -First 1)
    if ($fallback) { return $fallback[0] }
    return "alpine:latest"
}

$docker = Get-Docker
$configured = Read-EnvValue "AETHERIS_BACKUP_DIR"
if (-not $configured) {
    if (Test-Path -LiteralPath "F:\") {
        $configured = Ensure-BackupEnv "F:\PolaronBackup"
    } else {
        $configured = Ensure-BackupEnv (Join-Path $root "backup")
    }
}
if ($configured -eq "./backup" -or $configured -eq ".\backup") {
    $backup = Join-Path $root "backup"
} else {
    $backup = $configured
}

New-Item -ItemType Directory -Force -Path $backup | Out-Null
$readme = Join-Path $backup "README.txt"
@(
    "Polaron processing backup"
    ""
    "This folder holds disk and mobile job files, MinIO evidence objects,"
    "Ollama models, and Hugging Face caches. It is outside DockerDesktopWSL"
    "so processing does not keep expanding that WSL disk."
    ""
    "To move it to another drive:"
    "  1. Stop the Docker stack."
    "  2. Move this entire folder."
    "  3. Set AETHERIS_BACKUP_DIR in the project .env to the new path."
    "  4. Start the stack again."
    ""
    "Do not delete this folder while cases are still needed."
) | Set-Content -LiteralPath $readme -Encoding ascii

$copies = @(
    @{ Kind = "volume"; Name = "aetheris-forensic_minio_data"; Dest = "minio" },
    @{ Kind = "volume"; Name = "aetheris-forensic_ollama_data"; Dest = "ollama" },
    @{ Kind = "volume"; Name = "aetheris-forensic_huggingface_cache"; Dest = "huggingface" },
    @{ Kind = "volume"; Name = "aetheris-mobile-android_android_hf_cache"; Dest = "huggingface-android" },
    @{ Kind = "volume"; Name = "aetheris-mobile-ios_ios_hf_cache"; Dest = "huggingface-ios" },
    @{ Kind = "tree"; Source = (Join-Path $root "data"); Dest = "forensic-data" }
)

$pending = @($copies | Where-Object { -not (Test-Ready (Join-Path $backup $_.Dest)) })
if (-not $pending.Count) {
    Write-Host "Processing data is already in $backup"
    return
}

Write-Host "Moving processing data into $backup (this stays outside DockerDesktopWSL)..." -ForegroundColor Cyan
$running = @(& $docker ps --format "{{.Names}}" 2>$null | Where-Object {
    $_ -match '^(aetheris-forensic-|aetheris-mobile-android-|aetheris-mobile-ios-|aetheris-mobile-extract-|aetheris-vuln-|aetheris-common-minio)'
})
if ($running.Count) {
    Write-Host "Stopping containers that are writing job data..."
    & $docker stop @running | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not stop containers before moving processing data." }
}

$image = Get-CopyImage -Docker $docker
$copiedVolumes = New-Object System.Collections.Generic.List[string]
foreach ($item in $pending) {
    $dest = Join-Path $backup $item.Dest
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    if (Test-Ready $dest) { continue }
    $present = @(Get-ChildItem -Force -LiteralPath $dest | Where-Object { $_.Name -ne ".ready" -and $_.Name -ne "README.txt" })
    if ($present.Count -gt 0) {
        Write-Host "Keeping existing files in $dest"
        Mark-Ready $dest
        continue
    }

    if ($item.Kind -eq "volume") {
        & $docker volume inspect $item.Name 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) {
            Mark-Ready $dest
            continue
        }
        Write-Host "Copying Docker volume $($item.Name) -> $dest"
        $mount = ($dest -replace '\\', '/')
        & $docker run --rm --pull never -v "$($item.Name):/from:ro" -v "${mount}:/to" $image sh -c "tar -C /from -cf - . | tar -C /to -xf -"
        if ($LASTEXITCODE -ne 0) { throw "Failed to copy volume $($item.Name) into $dest" }
        Mark-Ready $dest
        $copiedVolumes.Add($item.Name) | Out-Null
        continue
    }

    if (Test-Path -LiteralPath $item.Source) {
        Write-Host "Copying $($item.Source) -> $dest"
        & robocopy $item.Source $dest /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "Failed to copy $($item.Source) (robocopy exit $LASTEXITCODE)" }
        $archived = "$($item.Source).pre-backup"
        if (-not (Test-Path -LiteralPath $archived)) {
            try {
                Rename-Item -LiteralPath $item.Source -NewName ((Split-Path -Leaf $item.Source) + ".pre-backup")
            } catch {
                Write-Warning "Copied job files, but the old folder is still in use: $($item.Source)"
            }
        }
    }
    Mark-Ready $dest
}

foreach ($name in $copiedVolumes) {
    $holders = @(& $docker ps -aq --filter "volume=$name")
    if ($holders.Count) {
        & $docker rm -f @holders | Out-Null
    }
    & $docker volume rm $name 1>$null 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Removed Docker volume $name from DockerDesktopWSL"
    } else {
        Write-Warning "Docker volume $name is still present. It can be removed after the stack is using the backup folder."
    }
}

Write-Host "Processing data is in $backup. Move that folder and update AETHERIS_BACKUP_DIR when you want it on another disk." -ForegroundColor Green
