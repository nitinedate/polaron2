"""Fast TCP port discovery used before local Greenbone scans.

The central Polaron scanner already reduces Greenbone work by probing the fast
candidate port set and passing only discovered TCP ports to OpenVAS.  The edge
scanner mirrors that behavior so client-side scans do not waste VT time on
known-closed ports.

This optimization is intentionally scoped to PORT_PROFILE=fast.  Operators
who explicitly select PORT_PROFILE=full retain the full T:1-65535 scan.
"""

from __future__ import annotations

import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

log = logging.getLogger("scanner_agent.port_discovery")

DEFAULT_FALLBACK_RANGE = "T:22,80,443,445,3389,8080"


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def parse_tcp_ports_from_range(spec: str) -> list[int]:
    """Expand a Greenbone TCP range (for example T:80,443,8000-8002)."""
    raw = (spec or "").strip()
    if raw.upper().startswith("T:"):
        raw = raw[2:]
    ports: set[int] = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if token.upper().startswith("T:"):
            token = token[2:]
        if "-" in token:
            left, right = token.split("-", 1)
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            lo = max(1, lo)
            hi = min(65535, hi)
            ports.update(range(lo, hi + 1))
            continue
        try:
            value = int(token)
        except ValueError:
            continue
        if 1 <= value <= 65535:
            ports.add(value)
    return sorted(ports)


def ports_to_gvm_range(ports: list[int], *, fallback: str = DEFAULT_FALLBACK_RANGE) -> str:
    clean = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    if not clean:
        return fallback
    return "T:" + ",".join(str(port) for port in clean)


def _timeout_sec() -> float:
    try:
        return max(0.05, min(5.0, float(os.environ.get("PORT_DISCOVERY_TIMEOUT_SEC") or 0.35)))
    except (TypeError, ValueError):
        return 0.35


def _worker_count(probe_count: int) -> int:
    try:
        configured = int(os.environ.get("PORT_DISCOVERY_WORKERS") or 64)
    except (TypeError, ValueError):
        configured = 64
    configured = max(1, min(256, configured))
    return max(1, min(probe_count or 1, configured))


def discover_open_tcp_ports(
    hosts: list[str],
    candidate_range: str,
    *,
    timeout: float | None = None,
    connector: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Probe the candidate TCP set concurrently and return per-host open ports."""
    clean_hosts = list(dict.fromkeys(str(host).strip() for host in hosts if str(host).strip()))
    candidate_ports = parse_tcp_ports_from_range(candidate_range)
    found: dict[str, list[int]] = {host: [] for host in clean_hosts}
    connect = connector or socket.create_connection
    probe_timeout = _timeout_sec() if timeout is None else max(0.01, float(timeout))
    probe_count = len(clean_hosts) * len(candidate_ports)

    if not clean_hosts or not candidate_ports:
        return {
            "by_host": found,
            "open_ports": [],
            "candidate_ports": candidate_ports,
            "probe_count": probe_count,
            "workers": 0,
            "timeout_sec": probe_timeout,
        }

    def _one(host: str, port: int) -> tuple[str, int, bool]:
        try:
            conn = connect((host, port), timeout=probe_timeout)
            # socket.create_connection returns a context-manager socket, while
            # tests may use a minimal close-only fake.
            try:
                close = getattr(conn, "close", None)
                if callable(close):
                    close()
            finally:
                pass
            return host, port, True
        except OSError:
            return host, port, False

    workers = _worker_count(probe_count)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="aetheris-port-probe") as pool:
        futures = [pool.submit(_one, host, port) for host in clean_hosts for port in candidate_ports]
        for future in as_completed(futures):
            host, port, is_open = future.result()
            if is_open:
                found[host].append(port)

    for host in found:
        found[host] = sorted(set(found[host]))
    open_ports = sorted({port for ports in found.values() for port in ports})
    return {
        "by_host": found,
        "open_ports": open_ports,
        "candidate_ports": candidate_ports,
        "probe_count": probe_count,
        "workers": workers,
        "timeout_sec": probe_timeout,
    }


def resolve_fast_scan_port_range(hosts: list[str], candidate_range: str) -> tuple[str, dict[str, Any]]:
    """Return the target range for a Fast edge scan plus discovery telemetry."""
    enabled = _env_bool("PORT_DISCOVERY_ENABLED", True)
    fallback = (os.environ.get("PORT_DISCOVERY_FALLBACK_RANGE") or DEFAULT_FALLBACK_RANGE).strip()
    if not enabled:
        return candidate_range, {
            "enabled": False,
            "fallback_used": False,
            "port_range": candidate_range,
            "by_host": {},
            "open_ports": [],
        }

    details = discover_open_tcp_ports(hosts, candidate_range)
    open_ports = list(details.get("open_ports") or [])
    fallback_used = not bool(open_ports)
    selected = ports_to_gvm_range(open_ports, fallback=fallback)
    details.update(
        {
            "enabled": True,
            "fallback_used": fallback_used,
            "port_range": selected,
        }
    )
    log.info(
        "Fast port discovery hosts=%d probes=%d workers=%d open_ports=%s selected_range=%s fallback=%s",
        len(hosts),
        int(details.get("probe_count") or 0),
        int(details.get("workers") or 0),
        open_ports,
        selected,
        fallback_used,
    )
    for host, ports in (details.get("by_host") or {}).items():
        log.info("Fast port discovery host=%s open_tcp=%s", host, ports)
    return selected, details
