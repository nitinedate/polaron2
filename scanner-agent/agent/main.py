"""Poll central API for edge scan jobs and run them on local OpenVAS."""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any

from agent.api_client import CentralApi
from agent.gmp_local import LocalOpenVAS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("scanner_agent")


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _cfg() -> dict[str, Any]:
    base = (os.environ.get("CENTRAL_API_URL") or "").strip()
    tenant = (os.environ.get("TENANT_SLUG") or "").strip()
    token = (os.environ.get("AGENT_TOKEN") or "").strip()
    if not base or not tenant or not token:
        log.error("CENTRAL_API_URL, TENANT_SLUG, and AGENT_TOKEN are required")
        sys.exit(1)
    return {
        "api": CentralApi(
            base_url=base,
            tenant=tenant,
            token=token,
            verify_tls=_env_bool("VERIFY_TLS", True),
        ),
        "openvas": LocalOpenVAS(),
        "poll": max(5, int(os.environ.get("POLL_INTERVAL_SEC") or 15)),
        "heartbeat": max(15, int(os.environ.get("HEARTBEAT_INTERVAL_SEC") or 60)),
        "stall_pct": float(os.environ.get("STALL_PROGRESS_PCT") or 95),
        "stall_sec": int(os.environ.get("STALL_SEC") or 180),
        "version": os.environ.get("AGENT_VERSION") or "1.0.0",
    }


def _run_job(cfg: dict[str, Any], job: dict[str, Any]) -> None:
    api: CentralApi = cfg["api"]
    openvas: LocalOpenVAS = cfg["openvas"]
    job_id = str(job["id"])
    targets = [t["target"] for t in (job.get("targets") or []) if t.get("target")]
    if not targets:
        api.patch_job(job_id, {"status": "failed", "error": "No targets in job"})
        return

    log.info("Claimed job %s targets=%s", job_id, targets)
    api.patch_job(job_id, {"status": "running", "progress_pct": 5, "message": "Starting local OpenVAS"})
    try:
        task_id = openvas.start_scan(name=f"edge-{job_id[:8]}", targets=targets)
    except Exception as exc:
        log.exception("Failed to start OpenVAS for job %s", job_id)
        api.patch_job(job_id, {"status": "failed", "error": str(exc)[:1500]})
        return

    api.patch_job(
        job_id,
        {
            "status": "running",
            "progress_pct": 10,
            "message": "OpenVAS running",
            "external_scan_id": task_id,
        },
    )

    last_progress = -1.0
    last_change = time.monotonic()
    poll = cfg["poll"]
    stall_pct = cfg["stall_pct"]
    stall_sec = cfg["stall_sec"]

    while True:
        time.sleep(poll)
        details = openvas.poll(task_id)
        status = details["status"]
        progress = float(details.get("progress") or 0)
        if progress != last_progress:
            last_progress = progress
            last_change = time.monotonic()
        api.patch_job(
            job_id,
            {
                "status": "running",
                "progress_pct": progress,
                "message": f"OpenVAS {details.get('gmp_status') or status}",
                "external_scan_id": task_id,
            },
        )

        if status == "completed":
            api.upload_results(
                job_id,
                {
                    "vulnerabilities": details.get("vulnerabilities") or [],
                    "status": "completed",
                    "external_scan_id": task_id,
                },
            )
            log.info("Job %s completed with %d vulns", job_id, len(details.get("vulnerabilities") or []))
            return

        if status in {"failed", "stopped"}:
            vulns = details.get("vulnerabilities") or []
            partial = status == "stopped" or bool(vulns)
            api.upload_results(
                job_id,
                {
                    "vulnerabilities": vulns,
                    "status": "completed" if vulns else "failed",
                    "external_scan_id": task_id,
                    "partial": partial,
                    "partial_reason": f"task {status} at {progress:.0f}%",
                    "error": None if vulns else f"OpenVAS ended with status {details.get('gmp_status')}",
                },
            )
            return

        if (
            stall_sec > 0
            and progress >= stall_pct
            and (time.monotonic() - last_change) >= stall_sec
        ):
            log.warning("Job %s stalled at %.0f%% — stopping and harvesting", job_id, progress)
            openvas.stop(task_id)
            time.sleep(3)
            details = openvas.poll(task_id)
            api.upload_results(
                job_id,
                {
                    "vulnerabilities": details.get("vulnerabilities") or [],
                    "status": "completed",
                    "external_scan_id": task_id,
                    "partial": True,
                    "partial_reason": f"stalled {stall_sec}s at >={stall_pct}%",
                },
            )
            return


def main() -> None:
    cfg = _cfg()
    api: CentralApi = cfg["api"]
    openvas: LocalOpenVAS = cfg["openvas"]
    next_heartbeat = 0.0
    log.info(
        "Scanner agent starting tenant=%s api=%s",
        os.environ.get("TENANT_SLUG"),
        os.environ.get("CENTRAL_API_URL"),
    )
    while True:
        now = time.monotonic()
        try:
            if now >= next_heartbeat:
                ready = openvas.ready()
                api.heartbeat(version=cfg["version"], openvas_ready=ready)
                next_heartbeat = now + cfg["heartbeat"]
                if not ready:
                    log.warning("Local OpenVAS not ready — will retry")
            job = api.next_job()
            if job:
                _run_job(cfg, job)
            else:
                time.sleep(cfg["poll"])
        except Exception:
            log.exception("Agent loop error")
            time.sleep(cfg["poll"])


if __name__ == "__main__":
    main()
