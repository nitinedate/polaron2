#!/usr/bin/env python3
"""Static release guard for the four vulnerability-scanner integration blockers."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    pack = read("scripts/pack-laptop-scanner-zip.ps1")
    require('$agentSrc = Join-Path $pkg "scanner-agent"' in pack, "packager must use laptop-scanner/scanner-agent")
    require("Legacy repo-root scanner-agent detected but intentionally NOT copied" in pack, "packager legacy-source guard missing")
    require("agent\\port_discovery.py" in pack, "packager does not validate port_discovery.py")
    require("tests\\test_target_progress.py" in pack, "packager does not validate target-progress tests")

    laptop_env = read("laptop-scanner/.env.example")
    laptop_compose = read("laptop-scanner/docker-compose.yml")
    gmp = read("laptop-scanner/scanner-agent/agent/gmp_local.py")
    root_env = read(".env.example")
    require("PORT_PROFILE=fast" in laptop_env, "laptop .env.example must default to Fast")
    require("GVM_OPTIMIZE_TEST=yes" in laptop_env, "laptop .env.example must default optimize_test=yes")
    require("PORT_PROFILE: ${PORT_PROFILE:-fast}" in laptop_compose, "laptop compose must default Fast")
    require("GVM_OPTIMIZE_TEST: ${GVM_OPTIMIZE_TEST:-yes}" in laptop_compose, "laptop compose must default optimize_test=yes")
    require('os.environ.get("PORT_PROFILE") or "fast"' in gmp, "LocalOpenVAS runtime fallback must be Fast")
    require("GVM_PORT_PROFILE=fast" in root_env, "central .env.example must default Fast")
    require("GVM_OPTIMIZE_TEST=true" in root_env, "central .env.example must default optimize_test=true")

    discovery = read("laptop-scanner/scanner-agent/agent/port_discovery.py")
    require("discover_open_tcp_ports" in discovery, "client open-port discovery implementation missing")
    require("resolve_fast_scan_port_range" in discovery, "client port-range resolver missing")
    require("resolve_fast_scan_port_range(host_list, FAST_PORTS)" in gmp, "LocalOpenVAS does not apply discovered port range")
    require("PORT_DISCOVERY_ENABLED=true" in laptop_env, "client port discovery must default enabled")

    router = read("backend/app/routers/scanner_agent.py")
    jobs = read("backend/app/services/scanner_agent_jobs.py")
    orch = read("backend/app/services/scan_orchestrator.py")
    ui = read("frontend/src/pages/vuln/ScanJobsPage.tsx")
    require("target_progress: dict[str, dict[str, Any]] | None = None" in router, "scanner API target_progress contract missing")
    require("_merge_edge_target_progress" in jobs and 'orch["target_progress"] = merged' in jobs, "backend target_progress persistence missing")
    require('orch.get("target_progress")' in orch and "scan_job_target_rows" in orch, "scan summary does not read persisted target progress")
    require("Per-IP scan activity" in ui, "React per-IP scan table missing")

    print("PASS: packaging canonical source")
    print("PASS: Fast/optimize defaults consistent")
    print("PASS: client open-port discovery feeds Greenbone target range")
    print("PASS: per-IP target_progress persists through backend to React")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
