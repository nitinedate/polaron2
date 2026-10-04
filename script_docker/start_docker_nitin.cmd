@echo off
setlocal
title Aetheris - start_docker_nitin
cd /d "%~dp0.."

echo.
echo  Building and starting Aetheris for the Nitin host.
echo  https://122.179.140.167
echo  https://future-softtech.co.in
echo  SSL certificates are created when they are missing.
echo  Add cache to rebuild images without the Docker layer cache.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_docker.ps1" -Profile nitin %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% neq 0 (
  echo  start_docker_nitin failed with exit code %ERR%.
) else (
  echo  start_docker_nitin finished.
)
echo.
pause
exit /b %ERR%
