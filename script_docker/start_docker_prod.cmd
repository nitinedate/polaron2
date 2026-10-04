@echo off
setlocal
title Aetheris - start_docker_prod
cd /d "%~dp0.."

echo.
echo  Building and starting Aetheris for the production host.
echo  https://122.179.141.248
echo  The SSL certificate is created when it is missing.
echo  Add cache to rebuild images without the Docker layer cache.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_docker.ps1" -Profile prod %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% neq 0 (
  echo  start_docker_prod failed with exit code %ERR%.
) else (
  echo  start_docker_prod finished.
)
echo.
pause
exit /b %ERR%
