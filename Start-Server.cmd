@echo off
setlocal
title Aetheris - Start Server Stack
cd /d "%~dp0"

echo.
echo  Starting Aetheris premise server stack...
echo  (drive mounts, host helper, GVM, ZAP/Trivy, API, workers, UI)
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-server.ps1" %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% neq 0 (
  echo  Startup failed with exit code %ERR%.
) else (
  echo  Startup finished.
)
echo.
pause
exit /b %ERR%
