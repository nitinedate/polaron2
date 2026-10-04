"""Artifact-inventory liveness (V45.2).

Problem
-------
``run_axiom_artifact_inventory`` refreshed its Redis job lock only at task
start and inside the *counting* callback. Every pre-count step (catalog ensure,
scope rows, extension census, path-token index, carve warm, URL/encryption
warm) ran silently: no disk-log line, no lock refresh. A step that took longer
than the 300 s lock TTL looked exactly like a dead worker — the supervisor
re-dispatched a second inventory task that then queued behind (or raced) the
first — while the UI sat at "0 / N (1%)" with no way to tell which step was slow.

Fix
---
``InventoryLiveness`` is a daemon thread that, for the lifetime of the run:

* refreshes the ``inventory`` job lock every ``refresh_sec`` (default 45 s);
* writes one ``disk_build_logs`` line every ``log_sec`` (default 90 s) naming
  the current sub-step and how long it has been running
  (``Artifact inventory liveness — extension census (142s) …``), which
  ``inventory_task_in_flight`` recognises as activity;
* records per-step durations so the final log says where the time went.

Use::

    with InventoryLiveness(schema_name, job_id) as live:
        live.step("catalog ensure")
        ...
        live.step("extension census")
        ...
    # live.timings -> {"catalog ensure": 1.2, "extension census": 141.9, ...}
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

log = logging.getLogger("inventory_liveness")

LIVENESS_PREFIX = "Artifact inventory liveness"


class InventoryLiveness:
    def __init__(
        self,
        schema_name: str | None,
        job_id: str,
        *,
        refresh_sec: float = 45.0,
        log_sec: float = 90.0,
    ) -> None:
        self.schema_name = schema_name
        self.job_id = job_id
        self.refresh_sec = max(float(refresh_sec), 10.0)
        self.log_sec = max(float(log_sec), 30.0)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._step = "starting"
        self._step_started = time.monotonic()
        self._run_started = time.monotonic()
        self._last_log = 0.0
        self.timings: dict[str, float] = {}
        self.extra: dict[str, Any] = {}

    # ------------------------------------------------------------------ public
    def step(self, name: str, **extra: Any) -> None:
        """Mark the start of a new sub-step; closes the previous one."""
        now = time.monotonic()
        with self._lock:
            prev = self._step
            self.timings[prev] = self.timings.get(prev, 0.0) + (now - self._step_started)
            self._step = str(name or "step")
            self._step_started = now
            self.extra = dict(extra)
        log.info("inventory job=%s step=%s", self.job_id, name)

    def current(self) -> tuple[str, float]:
        with self._lock:
            return self._step, time.monotonic() - self._step_started

    def elapsed(self) -> float:
        return time.monotonic() - self._run_started

    def summary(self) -> dict[str, float]:
        name, age = self.current()
        out = dict(self.timings)
        out[name] = out.get(name, 0.0) + age
        return {k: round(v, 1) for k, v in sorted(out.items(), key=lambda kv: -kv[1])}

    # --------------------------------------------------------------- lifecycle
    def __enter__(self) -> "InventoryLiveness":
        self._thread = threading.Thread(target=self._run, name=f"inv-live-{self.job_id[:8]}", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        name, age = self.current()
        self.timings[name] = self.timings.get(name, 0.0) + age

    # ---------------------------------------------------------------- internal
    def _refresh_lock(self) -> None:
        try:
            from app.services.job_locks import DEFAULT_INVENTORY_LOCK_TTL_SEC, refresh_job_lock

            refresh_job_lock("inventory", self.job_id, ttl_sec=DEFAULT_INVENTORY_LOCK_TTL_SEC)
        except Exception:
            log.debug("inventory lock refresh failed job=%s", self.job_id, exc_info=True)

    def _write_log(self) -> None:
        name, age = self.current()
        try:
            from app.db.session import firm_session
            from app.services.catalog_artifact_runner import INVENTORY_STAGE
            from app.services.disk_build_log import write_disk_log

            if not self.schema_name:
                return
            with firm_session(self.schema_name) as db:
                write_disk_log(
                    db,
                    self.job_id,
                    f"{LIVENESS_PREFIX} — {name} ({age:,.0f}s in step, {self.elapsed():,.0f}s total)",
                    stage=INVENTORY_STAGE,
                    metadata={
                        "liveness": True,
                        "step": name,
                        "step_sec": round(age, 1),
                        "total_sec": round(self.elapsed(), 1),
                        **{k: v for k, v in self.extra.items() if isinstance(v, (str, int, float, bool))},
                    },
                )
                db.commit()
        except Exception:
            log.debug("inventory liveness log failed job=%s", self.job_id, exc_info=True)

    def _run(self) -> None:
        last_refresh = 0.0
        while not self._stop.wait(5.0):
            now = time.monotonic()
            if now - last_refresh >= self.refresh_sec:
                self._refresh_lock()
                last_refresh = now
            if now - self._last_log >= self.log_sec:
                self._write_log()
                self._last_log = now
