@echo off
setlocal
title Aetheris - start_docker_local
cd /d "%~dp0.."

echo.
echo  Building and starting Aetheris on localhost.
echo  Forensic, Android, iOS, vulnerabilities, and the gateway.
echo  Add cache to rebuild images without the Docker layer cache.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_docker.ps1" -Profile local %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% neq 0 (
  echo  start_docker_local failed with exit code %ERR%.
) else (
  echo  start_docker_local finished.
)
echo.
pause
exit /b %ERR%
