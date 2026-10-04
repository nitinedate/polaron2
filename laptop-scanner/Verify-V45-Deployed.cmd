@echo off
setlocal
cd /d "%~dp0"
echo === V45 deployment check (laptop scanner) ===
echo.
echo [1] openvas.conf inside the scanner (expect plugins_timeout = 320, scanner_plugins_timeout = 36000):
docker compose exec -T openvas cat /etc/openvas/openvas.conf
echo.
echo [2] scanner-agent environment (expect PORT_PROFILE=full, UDP_PROFILE=priority, *_TIMEOUT_SEC=320/36000, SCAN_DEGRADED_RETRY=1):
docker compose exec -T scanner-agent sh -c "env | grep -E '^(PORT_PROFILE|UDP_PROFILE|PLUGINS_TIMEOUT_SEC|SCANNER_PLUGINS_TIMEOUT_SEC|GVM_OPTIMIZE_TEST|GVM_MAX_CHECKS|SCAN_IP_MAX_PARALLELISM|SCAN_DEGRADED_RETRY|AGENT_VERSION)=' | sort"
echo.
echo [3] last 'OpenVAS quality profile' line the agent logged (must say plugins_timeout=320s scanner_plugins_timeout=36000s):
docker compose logs --tail 2000 scanner-agent 2>nul | findstr /C:"OpenVAS quality profile" | more +0
echo.
echo If [1] still shows 60/90 the V45 compose/env was not applied: run
echo    docker compose up -d --force-recreate configure-openvas openvas ospd-openvas scanner-agent
pause
