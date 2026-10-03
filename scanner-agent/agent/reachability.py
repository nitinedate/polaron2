"""Fast, coverage-safe host discovery and common-port discovery for edge scans.

The old implementation treated a TCP connection refusal as if the host were
unreachable. A refusal is actually strong evidence that the host is alive. This
module separates liveness from open-port discovery and treats timeout-only
probes as inconclusive (scan by default) instead of silently dropping targets.
"""

from __future__ import annotations

import errno
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agent.ip_audit import emit_ip_event

log = logging.getLogger("scanner_agent.reachability")

_FAST_PORTS_DEFAULT = (
    "21-23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,587,631,993,995,"
    "1433,1521,1723,2049,3000,3306,3389,5432,5672,5900,5985,6379,6443,"
    "8080,8443,9000,9418,27017"
)


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _parse_ports(raw: str) -> list[int]:
    out: list[int] = []
    for part in str(raw or "").replace("T:", "").split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            left, right = token.split("-", 1)
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                continue
            for port in range(max(1, lo), min(65535, hi) + 1):
                if port not in out:
                    out.append(port)
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in out:
            out.append(port)
    return out


def _ports() -> list[int]:
    raw = (os.environ.get("PORT_DISCOVERY_PORTS") or os.environ.get("REACHABILITY_PORTS") or _FAST_PORTS_DEFAULT).strip()
    out = _parse_ports(raw)
    return out or [22, 80, 443, 445, 3389]


def _timeout_sec() -> float:
    raw = os.environ.get("PORT_DISCOVERY_TIMEOUT_SEC") or os.environ.get("REACHABILITY_TIMEOUT_SEC") or "0.35"
    try:
        return max(0.1, min(3.0, float(raw)))
    except (TypeError, ValueError):
        return 0.35


def _workers(target_count: int) -> int:
    try:
        configured = int(os.environ.get("REACHABILITY_WORKERS") or 10)
    except (TypeError, ValueError):
        configured = 10
    return max(1, min(target_count or 1, max(5, min(16, configured))))


def _per_host_workers(port_count: int) -> int:
    try:
        configured = int(os.environ.get("PORT_DISCOVERY_WORKERS_PER_HOST") or 12)
    except (TypeError, ValueError):
        configured = 12
    return max(1, min(port_count or 1, max(4, min(24, configured))))


def _probe_port(host: str, port: int, timeout: float) -> tuple[int, str, str | None]:
    """Return (port, state, error_name).

    state is one of: open, closed_alive, unreachable, timeout, error.
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return int(port), "open", None
    except ConnectionRefusedError as exc:
        return int(port), "closed_alive", exc.__class__.__name__
    except socket.timeout as exc:
        return int(port), "timeout", exc.__class__.__name__
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ECONNREFUSED:
            return int(port), "closed_alive", exc.__class__.__name__
        if getattr(exc, "errno", None) in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN}:
            return int(port), "unreachable", exc.__class__.__name__
        if getattr(exc, "errno", None) in {errno.ETIMEDOUT}:
            return int(port), "timeout", exc.__class__.__name__
        return int(port), "error", exc.__class__.__name__


def probe_host(
    host: str,
    *,
    ports: list[int] | None = None,
    timeout: float | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    h = (host or "").strip()
    if not h:
        return {"host": h, "reachable": False, "open_port": None, "open_ports": [], "attempted_ports": [], "errors": [], "probe_state": "invalid"}

    try:
        import ipaddress
        ipaddress.ip_address(h)
    except ValueError:
        # CIDR/range/hostname expressions stay delegated to OpenVAS.
        return {"host": h, "reachable": True, "open_port": None, "open_ports": [], "attempted_ports": [], "errors": [], "probe_state": "delegated"}

    port_list = list(ports if ports is not None else _ports())
    to = timeout if timeout is not None else _timeout_sec()
    attempted = list(port_list)
    errors: list[dict[str, Any]] = []
    open_ports: list[int] = []
    saw_alive = False
    states: list[str] = []

    with ThreadPoolExecutor(max_workers=_per_host_workers(len(port_list)), thread_name_prefix="aetheris-port") as pool:
        futs = [pool.submit(_probe_port, h, port, to) for port in port_list]
        for fut in as_completed(futs):
            port, state, err = fut.result()
            states.append(state)
            if state == "open":
                open_ports.append(port)
                saw_alive = True
            elif state == "closed_alive":
                # TCP RST/refusal proves there is a host at the address even though
                # this particular service is closed.
                saw_alive = True
            if err:
                errors.append({"port": port, "state": state, "error": err})

    open_ports = sorted(set(open_ports))
    hard_unreachable = bool(states) and all(state == "unreachable" for state in states)
    inconclusive = not saw_alive and not hard_unreachable
    unknown_policy = (os.environ.get("REACHABILITY_UNKNOWN_POLICY") or "scan").strip().lower()
    reachable = bool(saw_alive or (inconclusive and unknown_policy != "skip"))
    probe_state = "alive" if saw_alive else ("unreachable" if hard_unreachable else "inconclusive")

    if job_id:
        if reachable:
            emit_ip_event(
                job_id,
                h,
                "discovery",
                status="pending",
                open_ports=open_ports,
                attempted_ports=attempted,
                probe_state=probe_state,
                activity=(
                    f"Discovery complete - {len(open_ports)} open port(s)"
                    if open_ports
                    else "Discovery inconclusive - continuing scan for coverage"
                    if inconclusive
                    else "Host reachable"
                ),
            )
        else:
            emit_ip_event(
                job_id,
                h,
                "unreachable",
                attempted_ports=attempted,
                reason="network_unreachable" if hard_unreachable else "probe_inconclusive_policy_skip",
            )

    return {
        "host": h,
        "reachable": reachable,
        "open_port": open_ports[0] if open_ports else None,
        "open_ports": open_ports,
        "attempted_ports": attempted,
        "errors": errors,
        "probe_state": probe_state,
        "inconclusive": inconclusive,
    }


def host_reachable(host: str, *, ports: list[int] | None = None, timeout: float | None = None) -> bool:
    return bool(probe_host(host, ports=ports, timeout=timeout).get("reachable"))


def partition_targets(targets: list[str], *, job_id: str | None = None) -> dict[str, Any]:
    """Split targets concurrently while preserving user-selected order."""
    enabled = _env_bool("SKIP_UNREACHABLE_TARGETS", True)
    clean = [str(t).strip() for t in targets if str(t).strip()]
    if not enabled:
        for host in clean:
            if job_id:
                emit_ip_event(job_id, host, "queued", reachability_filter=False)
        return {"enabled": False, "reachable": clean, "unreachable": [], "skipped_hosts": [], "probe_results": {}}

    reachable: list[str] = []
    unreachable: list[str] = []
    results: dict[str, dict[str, Any]] = {}
    max_workers = _workers(len(clean))

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="aetheris-reach") as pool:
        future_map = {pool.submit(probe_host, host, job_id=job_id): host for host in clean}
        for fut in as_completed(future_map):
            host = future_map[fut]
            try:
                result = fut.result()
            except Exception as exc:
                # Discovery failure must not silently remove an authorized target.
                result = {
                    "host": host,
                    "reachable": True,
                    "open_port": None,
                    "open_ports": [],
                    "attempted_ports": [],
                    "errors": [{"error": exc.__class__.__name__}],
                    "probe_state": "probe_error_scan_anyway",
                    "inconclusive": True,
                }
                if job_id:
                    emit_ip_event(job_id, host, "discovery", status="pending", activity="Discovery error - continuing scan for coverage", error=exc.__class__.__name__)
            results[host] = result

    for host in clean:
        result = results.get(host) or {"reachable": True, "open_ports": [], "probe_state": "missing_scan_anyway"}
        if result.get("reachable"):
            reachable.append(host)
        else:
            unreachable.append(host)
            log.info("Eliminating network-unreachable target %s from OpenVAS scan set", host)

    skipped = [{"host": h, "reason": "unreachable"} for h in unreachable]
    return {
        "enabled": True,
        "reachable": reachable,
        "unreachable": unreachable,
        "skipped_hosts": skipped,
        "probe_results": results,
        "probe_workers": max_workers,
    }
