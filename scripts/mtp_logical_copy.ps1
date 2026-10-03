# Standalone MTP shared-storage copy for AndroidMtpAdapter / any laptop.
param(
    [string]$InstanceId = "",
    [string]$DeviceName = "",
    [string]$DestDir,
    [string]$LogPath,
    [string]$OsHint = "android"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here "host-mobile-acquire.ps1")

if (-not $DestDir) { throw "DestDir is required" }
if (-not $LogPath) { $LogPath = Join-Path $DestDir "mtp_copy.log" }

$result = Copy-MtpDeviceLogical `
    -DeviceName $DeviceName `
    -InstanceId $InstanceId `
    -DestDir $DestDir `
    -LogPath $LogPath `
    -OsHint $OsHint

($result | ConvertTo-Json -Compress -Depth 4)
if (-not $result.ok) { exit 1 }
exit 0
