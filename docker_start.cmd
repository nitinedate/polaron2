@echo off
setlocal
title Aetheris - docker_start
cd /d "%~dp0"

echo.
echo  Building and starting Aetheris Docker stacks with HTTPS.
echo  Static IP: https://122.179.141.248/
echo  Add -Cache or cache to rebuild images without the Docker layer cache.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0docker_start.ps1" %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% neq 0 (
  echo  docker_start failed with exit code %ERR%.
) else (
  echo  docker_start finished.
)
echo.
pause
exit /b %ERR%
