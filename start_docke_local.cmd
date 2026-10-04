@echo off
setlocal
title Aetheris - start_docke_local
cd /d "%~dp0"

echo.
echo  Building and starting Aetheris Docker stacks on localhost.
echo  Forensic, Android, iOS, vulnerabilities, and the gateway.
echo  Add cache to rebuild images without the Docker layer cache.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_docke_local.ps1" %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% neq 0 (
  echo  start_docke_local failed with exit code %ERR%.
) else (
  echo  start_docke_local finished.
)
echo.
pause
exit /b %ERR%
