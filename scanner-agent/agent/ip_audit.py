"""Per-IP durable audit logging and asynchronous central status delivery.

Each IP keeps a local JSONL audit trail. Important state transitions are also
queued to the central API without blocking discovery/OpenVAS worker threads.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("scanner_agent.ip")
_lock = threading.Lock()
_sink: Callable[[dict[str, Any]], Any] | None = None
_sink_queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=2000)
_sink_thread: threading.Thread | None = None
_sink_stop = threading.Event()

_REMOTE_EVENTS = {
    "queued",
    "reachable",
    "discovery",
    "discovered",
    "unreachable",
    "start_attempt",
    "started",
    "resumed",
    "progress",
    "completed",
    "scan_failed",
    "start_error",
    "poll_error",
    "ip_timeout",
    "skipped",
}


def _safe(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip())
    return text[:160] or "unknown"


def _root() -> Path:
    return Path(os.environ.get("IP_SCAN_LOG_DIR") or "/app/logs/ip")


def _sink_loop() -> None:
    while not _sink_stop.is_set():
        try:
            payload = _sink_queue.get(timeout=0.25)
        except queue.Empty:
            continue
        try:
            callback = _sink
            if callback is not None:
                callback(payload)
        except Exception:
            log.warning(
                "Central per-IP event delivery failed job=%s ip=%s event=%s",
                payload.get("job_id"),
                payload.get("ip"),
                payload.get("event"),
                exc_info=True,
            )
        finally:
            _sink_queue.task_done()


def set_ip_event_sink(callback: Callable[[dict[str, Any]], Any] | None) -> None:
    """Register a best-effort remote event sink; delivery is asynchronous."""
    global _sink, _sink_thread
    _sink = callback
    if callback is not None and (_sink_thread is None or not _sink_thread.is_alive()):
        _sink_stop.clear()
        _sink_thread = threading.Thread(target=_sink_loop, name="ip-event-sink", daemon=True)
        _sink_thread.start()


def flush_ip_events(timeout: float = 5.0) -> bool:
    """Wait briefly for queued target events before terminal result upload/exit."""
    deadline = time.monotonic() + max(0.0, float(timeout))
    while _sink_queue.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.05)
    return _sink_queue.unfinished_tasks == 0


def emit_ip_event(job_id: str, host: str, event: str, **fields: Any) -> None:
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "job_id": str(job_id or ""),
        "ip": str(host or ""),
        "event": str(event or "event"),
    }
    for key, value in fields.items():
        if value is not None:
            payload[str(key)] = value
    line = json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))

    try:
        folder = _root() / _safe(job_id)
        path = folder / f"{_safe(host)}.jsonl"
        summary = folder / "all-ips.jsonl"
        with _lock:
            folder.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            with summary.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        log.debug("Unable to persist per-IP audit file", exc_info=True)

    level = logging.WARNING if event in {"start_error", "poll_error", "scan_failed", "unreachable", "ip_timeout", "skipped"} else logging.INFO
    log.log(level, "IP_EVENT %s", line, extra={"job_id": str(job_id or "")})

    if _sink is not None and str(event or "").lower() in _REMOTE_EVENTS:
        try:
            _sink_queue.put_nowait(dict(payload))
        except queue.Full:
            log.warning("Per-IP central event queue full; dropping event job=%s ip=%s event=%s", job_id, host, event)
