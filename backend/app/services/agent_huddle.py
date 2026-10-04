"""Observe / Performance / Repair huddle — they confer and keep every lane moving."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import execute, fetchone
from app.services.disk_build_log import write_disk_log
from app.services.pipeline_heal import record_heal_event

log = logging.getLogger("agent_huddle")

_CPU_ACTIONS = frozenset(
    {
        "parse_drain",
        "artifact_inventory",
        "graph_sync",
        "rag_enrich",
        "resume_extraction",
        "start_phase3",
    }
)
_GPU_ACTIONS = frozenset({"resume_rag", "force_finish_rag"})


def _gpu_at_abort() -> tuple[bool, float | None]:
    """Only block new GPU work at the abort margin. Warm is OK."""
    settings = get_settings()
    if not settings.gpu_thermal_enabled:
        return False, None
    try:
        from app.services.gpu_thermal import get_gpu_stats

        stats = get_gpu_stats()
        if not stats.available or stats.temperature_c is None:
            return False, None
        abort = int(getattr(settings, "gpu_thermal_abort_c", 94) or 94)
        return stats.temperature_c >= abort, float(stats.temperature_c)
    except Exception:
        return False, None


def observe_pipeline_snapshot(db, job_id: str) -> dict[str, Any]:
    """Observe agent — what is pending, stalled, or already moving."""
    row = fetchone(
        db,
        """SELECT id, status, error, updated_at, stop_requested, extracted_disk_uri,
                  files_total, files_extracted, pipeline_progress, disk_source, segment_readiness
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    snap: dict[str, Any] = {
        "job_id": job_id,
        "row": row,
        "status": (row or {}).get("status") or "",
        "stop_requested": bool((row or {}).get("stop_requested")),
        "parse_pending": 0,
        "ocr_pending": 0,
        "ocr_done": 0,
        "ocr_eligible": 0,
        "rag_remaining": 0,
        "chunk_n": 0,
        "inventory": {"total": 0, "completed": 0, "done": True},
        "inventory_inflight": False,
        "graph_status": "",
        "enrich_done": False,
        "enrich_busy": False,
        "enrich_lock_held": False,
        "enrich_scanned": 0,
        "enrich_parse_total": 0,
        "files_total": int((row or {}).get("files_total") or 0),
        "files_done": int((row or {}).get("files_extracted") or 0),
        "extract_live": False,
        "lanes": {},
        "artifact_n": 0,
        "drives_ready": False,
        "mounted_letters": [],
        "windows_letters": [],
        "missing_letters": [],
        "client_upload": False,
        "list_folder_done": False,
        "is_mobile": False,
        "mobile_platform": None,
        "owner_agent": None,
        "notes": [],
        "agent_states": {},
        "intake_started": False,
    }
    if not row or snap["stop_requested"]:
        snap["notes"].append("job stopped or missing")
        return snap

    try:
        from app.services.pipeline_orchestrator import pipeline_intake_started

        snap["intake_started"] = pipeline_intake_started(row)
    except Exception as exc:
        snap["notes"].append(f"intake gate: {exc}"[:120])
        snap["intake_started"] = False
    if not snap["intake_started"]:
        snap["notes"].append("waiting for examiner evidence selection")
        return snap

    try:
        from app.forensic_common.job_types import is_mobile_job, mobile_os_family
        from app.services.mobile_platform_agents import owner_agent_id

        snap["is_mobile"] = is_mobile_job(db, job_id)
        snap["mobile_platform"] = mobile_os_family(db, job_id)
        snap["owner_agent"] = owner_agent_id(snap["mobile_platform"])
        if snap["is_mobile"]:
            snap["list_folder_done"] = True
    except Exception as exc:
        snap["notes"].append(f"platform owner: {exc}"[:120])

    raw_pp = (row or {}).get("pipeline_progress")
    if isinstance(raw_pp, str):
        try:
            raw_pp = json.loads(raw_pp)
        except Exception:
            raw_pp = {}
    if isinstance(raw_pp, dict):
        orch = raw_pp.get("orchestration") if isinstance(raw_pp.get("orchestration"), dict) else {}
        snap["agent_states"] = orch.get("agents") if isinstance(orch.get("agents"), dict) else {}

    try:
        from app.services.job_locks import extract_is_live, inspect_process_lanes

        snap["extract_live"] = extract_is_live(db, job_id, row)
        snap["lanes"] = inspect_process_lanes(job_id)
    except Exception as exc:
        snap["notes"].append(f"extract live check failed: {exc}"[:120])

    try:
        from app.services.agent_duties import extract_agent_health
        from app.services.disk import restore_status_if_extract_complete

        snap["extract_health"] = extract_agent_health(snap)
        if snap["extract_health"].get("stuck_restarting"):
            restored = restore_status_if_extract_complete(db, job_id)
            if restored:
                snap["status"] = restored
                if isinstance(snap.get("row"), dict):
                    snap["row"]["status"] = restored
                write_disk_log(
                    db,
                    job_id,
                    f"Extraction Agent: copy complete — standing down, status {restored}",
                    stage="extract",
                )
            if snap.get("lanes", {}).get("extract_lock"):
                try:
                    from app.services.job_locks import force_release_job_lock

                    force_release_job_lock("extract", job_id)
                except Exception:
                    pass
            snap["extract_live"] = False
            snap["extract_health"] = extract_agent_health(snap)
            db.commit()
    except Exception as exc:
        snap["notes"].append(f"extract complete check failed: {exc}"[:120])

    try:
        from app.services.host_evidence import ensure_folder_listed, is_client_upload_pending, listing_complete
        from app.services.mobile_os import load_job_disk_source

        ds = load_job_disk_source(row)

        if str(ds.get("intake") or "") == "browser_upload":
            snap["client_upload"] = True
            snap["drives_ready"] = True
        elif not (ds.get("evidence_folder") or ds.get("path") or ds.get("host_path")):
            # No folder yet. Remote browsers upload from their PC — do not remount office disks.
            snap["drives_ready"] = True
        pending_upload = is_client_upload_pending(ds)
        snap["client_upload_pending"] = pending_upload
        from app.services.download_agent import DOWNLOAD_PARALLELISM, download_counts

        recv, exp = download_counts(ds)
        snap["download_received"] = recv
        snap["download_expected"] = exp
        snap["download_parallelism"] = DOWNLOAD_PARALLELISM
        snap["list_folder_done"] = False if pending_upload else listing_complete(db, job_id)
        early_list = str(snap.get("status") or "").lower() in (
            "created",
            "registered",
            "pending",
            "uploaded",
            "awaiting_segments",
        )
        if (
            not pending_upload
            and not snap["list_folder_done"]
            and early_list
            and (ds.get("evidence_folder") or ds.get("last_host_path") or ds.get("path") or ds.get("staging_container_path"))
        ):
            ensure_folder_listed(db, job_id)
            snap["list_folder_done"] = listing_complete(db, job_id)
    except Exception as exc:
        snap["notes"].append(f"list folder: {exc}"[:120])
    status_l = str(snap.get("status") or "").lower()
    if (
        not snap.get("list_folder_done")
        and status_l not in ("created", "registered", "pending", "uploaded", "awaiting_segments")
        and (snap.get("agent_states") or {}).get("list_folder_agent", {}).get("state") == "done"
    ):
        snap["list_folder_done"] = True

    try:
        from app.services.drive_mount_agent import (
            inspect_host_letters,
            missing_windows_letters,
            mounted_letters,
            mounts_ready,
            windows_attached_letters,
        )
        from app.services.hostdrive_agent import probe_helper

        mount_done = (snap.get("agent_states") or {}).get("drive_mount_agent", {}).get("state") == "done"
        if mount_done or snap.get("client_upload"):
            snap["drives_ready"] = True
        else:
            helper = probe_helper()
            rows = inspect_host_letters()
            letters = mounted_letters(rows)
            windows = windows_attached_letters(helper) if helper.get("ok") else []
            missing = missing_windows_letters(helper, rows) if helper.get("ok") else []
            snap["mounted_letters"] = letters
            snap["windows_letters"] = windows
            snap["missing_letters"] = missing
            snap["drives_ready"] = mounts_ready(rows, helper)
            if missing:
                snap["notes"].append("Windows letters not in Docker: " + ", ".join(missing))
    except Exception as exc:
        snap["notes"].append(f"drive mount inspect failed: {exc}"[:120])

    try:
        from app.services.artifact_parse import count_pending_parse

        snap["parse_pending"] = int(count_pending_parse(db, job_id) or 0)
    except Exception as exc:
        snap["notes"].append(f"parse count failed: {exc}"[:120])

    try:
        art = fetchone(
            db,
            "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )
        snap["artifact_n"] = int((art or {}).get("c") or 0)
    except Exception:
        pass

    settings = get_settings()
    if settings.ocr_enabled:
        try:
            from app.services.ocr_gpu import (
                count_ocr_eligible,
                count_ocr_unfinished,
                count_pending_ocr,
                enqueue_eligible_ocr,
                reopen_failed_ocr_without_results,
                skip_ocr_noise_pending,
                write_ocr_live_progress,
            )

            ocr_st = (snap.get("agent_states") or {}).get("ocr_agent") or {}
            status_l = str(snap.get("status") or "").lower()
            early = status_l in (
                "created",
                "registered",
                "pending",
                "uploaded",
                "awaiting_segments",
            ) and int(snap.get("artifact_n") or 0) <= 0
            ocr_already_done = ocr_st.get("state") == "done"
            if not early and not ocr_already_done:
                skipped = skip_ocr_noise_pending(db, job_id)
                queued = enqueue_eligible_ocr(db, job_id)
                healed = reopen_failed_ocr_without_results(db, job_id)
                queued += healed
                if skipped or queued:
                    write_ocr_live_progress(
                        db,
                        job_id,
                        label=(
                            f"OCR — skipped {skipped:,} photos/cache; GLM only for scans"
                            if skipped
                            else f"OCR — queued {queued:,} document(s)"
                        ),
                    )
                    db.commit()
            snap["ocr_pending"] = int(count_pending_ocr(db, job_id) or 0)
            snap["ocr_eligible"] = int(count_ocr_eligible(db, job_id) or 0)
            snap["ocr_unfinished"] = int(count_ocr_unfinished(db, job_id) or 0)
            done_row = fetchone(
                db,
                "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND ocr_status='done'",
                {"jid": job_id},
            )
            snap["ocr_done"] = int((done_row or {}).get("c") or 0)
            from app.services.agent_duties import ocr_queue_health

            snap["ocr_health"] = ocr_queue_health(snap)
            if (
                not early
                and ocr_already_done
                and (int(snap["ocr_pending"]) > 0 or int(snap["ocr_unfinished"]) > 0)
            ):
                queued = enqueue_eligible_ocr(db, job_id)
                healed = reopen_failed_ocr_without_results(db, job_id)
                if queued or healed:
                    db.commit()
                snap["ocr_pending"] = int(count_pending_ocr(db, job_id) or 0)
                snap["ocr_unfinished"] = int(count_ocr_unfinished(db, job_id) or 0)
                snap["ocr_health"] = ocr_queue_health(snap)
            try:
                from app.services.pipeline_orchestrator import (
                    _parse_pp,
                    _set_agent,
                    ocr_agent_progress,
                    reset_pre_extract_agent_cards,
                )

                row_pp = fetchone(
                    db,
                    "SELECT pipeline_progress FROM jobs WHERE id=:id",
                    {"id": job_id},
                )
                pp = _parse_pp((row_pp or {}).get("pipeline_progress"))
                orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
                states = orch.get("agents") if isinstance(orch.get("agents"), dict) else {}
                if not states:
                    pass
                elif early:
                    reset_pre_extract_agent_cards(states)
                    orch["agents"] = states
                    if orch.get("current_agent_id") == "ocr_agent":
                        orch["current_agent_id"] = "list_folder_agent"
                        orch["current_agent_label"] = "List folder"
                        orch["current_agent_state"] = "running"
                    pp["orchestration"] = orch
                    execute(
                        db,
                        "UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id",
                        {"pp": json.dumps(pp), "id": job_id},
                    )
                else:
                    extract_incomplete = status_l in (
                        "processing",
                        "building_disk",
                        "extracting",
                        "created",
                        "registered",
                    )
                    view = ocr_agent_progress(
                        ocr_done=int(snap["ocr_done"]),
                        ocr_pending=int(snap["ocr_pending"]),
                        ocr_eligible=int(snap["ocr_eligible"]),
                        parse_pending=int(snap.get("parse_pending") or 0),
                        extract_incomplete=extract_incomplete and int(snap.get("artifact_n") or 0) <= 0,
                        artifacts_registered=int(snap.get("artifact_n") or 0),
                        ocr_unfinished=int(snap.get("ocr_unfinished") or 0),
                    )
                    _set_agent(states, "ocr_agent", **view)
                    if view.get("state") == "running":
                        orch["current_agent_id"] = "ocr_agent"
                        orch["current_agent_label"] = "OCR enrich"
                        orch["current_agent_state"] = "running"
                    elif view.get("state") == "done" and orch.get("current_agent_id") == "ocr_agent":
                        orch["current_agent_state"] = "done"
                        entity = states.get("entity_agent") if isinstance(states.get("entity_agent"), dict) else {}
                        if (entity.get("state") or "pending") != "done":
                            orch["current_agent_id"] = "entity_agent"
                            orch["current_agent_label"] = "Entity extraction"
                            orch["current_agent_state"] = entity.get("state") or "pending"
                    orch["agents"] = states
                    pp["orchestration"] = orch
                    execute(
                        db,
                        "UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id",
                        {"pp": json.dumps(pp), "id": job_id},
                    )
            except Exception:
                pass
        except Exception:
            snap["ocr_pending"] = 0
            snap["ocr_done"] = 0
            snap["ocr_eligible"] = 0
            snap["ocr_unfinished"] = 0
            try:
                from app.services.agent_duties import ocr_queue_health as _ocr_health

                snap["ocr_health"] = _ocr_health(snap)
            except Exception:
                snap["ocr_health"] = {}

    try:
        from app.services.dual_rag_index import _count_indexable_without_chunks

        snap["rag_remaining"] = int(_count_indexable_without_chunks(db, job_id) or 0)
        cr = fetchone(
            db,
            "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
            {"jid": job_id},
        )
        snap["chunk_n"] = int((cr or {}).get("c") or 0)
    except Exception:
        pass

    try:
        from app.services.catalog_artifact_runner import (
            axiom_inventory_progress,
            inventory_task_in_flight,
        )

        snap["inventory"] = axiom_inventory_progress(db, job_id)
        snap["inventory_inflight"] = bool(inventory_task_in_flight(db, job_id))
    except Exception:
        pass

    try:
        gs = fetchone(
            db,
            "SELECT status, last_sync_at FROM graph_sync_state WHERE job_id=:jid",
            {"jid": job_id},
        )
        snap["graph_status"] = (gs or {}).get("status") or ""
        from app.services.pipeline_supervisor import _recent_supervisor_action

        snap["graph_stale"] = bool(
            snap["graph_status"] in ("queued", "syncing")
            and not (gs or {}).get("last_sync_at")
            and not _recent_supervisor_action(db, job_id, "graph_agent", within_sec=90.0)
        )
    except Exception:
        snap["graph_status"] = ""

    try:
        from app.services.pipeline_orchestrator import _rag_enrich_status

        done, busy = _rag_enrich_status(db, job_id)
        snap["enrich_done"] = bool(done)
        try:
            from app.services.rag_enrich import load_enrichment_stats

            stats = load_enrichment_stats(db, job_id)
            snap["enrich_scanned"] = int(stats.get("scanned") or 0)
            snap["enrich_parse_total"] = int(stats.get("parse_total") or 0)
            snap["enrich_updated_at"] = stats.get("updated_at")
        except Exception:
            snap.setdefault("enrich_scanned", 0)
            snap.setdefault("enrich_parse_total", 0)
        try:
            from app.services.job_locks import job_lock_age_sec, job_lock_held

            snap["enrich_lock_held"] = bool(job_lock_held("rag_enrich", job_id))
            snap["enrich_lock_age_sec"] = job_lock_age_sec("rag_enrich", job_id)
        except Exception:
            snap["enrich_lock_held"] = False
            snap["enrich_lock_age_sec"] = None
        # Live only if a worker holds the lock. A dispatch log is not progress.
        snap["enrich_busy"] = bool(snap["enrich_lock_held"])
        from app.services.agent_duties import enrich_agent_health

        snap["enrich_health"] = enrich_agent_health(snap)
        if snap["enrich_health"].get("frozen") and snap.get("enrich_lock_held"):
            from app.services.job_locks import force_release_job_lock

            force_release_job_lock("rag_enrich", job_id)
            snap["enrich_lock_held"] = False
            snap["enrich_lock_age_sec"] = None
            snap["enrich_busy"] = False
            restarted = enrich_agent_health(snap)
            restarted["frozen"] = True
            restarted["should_run"] = True
            snap["enrich_health"] = restarted
            snap["notes"].append("Entity Agent: released frozen rag_enrich lock")
    except Exception:
        snap["enrich_done"] = False
        snap["enrich_busy"] = False
        snap["enrich_lock_held"] = False
        snap["enrich_health"] = {}

    try:
        from app.services.host_capacity import probe_host

        host = probe_host()
        snap["cpu_temp_c"] = host.cpu_temp_c
        if host.gpu_temp_c is not None:
            snap["gpu_temp_c"] = host.gpu_temp_c
    except Exception:
        snap.setdefault("cpu_temp_c", None)

    try:
        from app.services.agent_duties import assess_chassis_for_ocr, ocr_queue_health

        if "ocr_health" not in snap:
            snap["ocr_health"] = ocr_queue_health(snap)
        snap["chassis"] = assess_chassis_for_ocr(snap.get("gpu_temp_c"), snap.get("cpu_temp_c"))
    except Exception:
        snap.setdefault("ocr_health", {})
        snap.setdefault("chassis", {})
    return snap


def _observe_speech(snap: dict[str, Any], gpu_temp: float | None, gpu_abort: bool) -> str:
    inv = snap.get("inventory") or {}
    health = snap.get("ocr_health") if isinstance(snap.get("ocr_health"), dict) else {}
    chassis = snap.get("chassis") if isinstance(snap.get("chassis"), dict) else {}
    ocr_pending = int(health.get("pending") if health else snap.get("ocr_pending") or 0)
    ocr_unfinished = int(health.get("unfinished") if health else snap.get("ocr_unfinished") or 0)
    parts = [
        f"status={snap.get('status')}",
        f"parse {snap.get('parse_pending') or 0:,} pending",
        f"OCR {ocr_pending:,} pending / {ocr_unfinished:,} unfinished",
        f"RAG {snap.get('chunk_n') or 0:,} chunks / {snap.get('rag_remaining') or 0:,} left",
        f"inventory {inv.get('completed') or 0:,}/{inv.get('total') or 0:,}",
        f"graph={snap.get('graph_status') or 'idle'}",
    ]
    if snap.get("client_upload_pending"):
        parts.insert(
            1,
            (
                f"Download Agent blocking all others "
                f"({snap.get('download_received') or 0}/{snap.get('download_expected') or '?'} "
                f"parallelism={snap.get('download_parallelism') or 3})"
            ),
        )
    if health.get("skipped_gap") or health.get("fake_running"):
        parts.append("OCR Agent: queue empty — skipped gap is finished, not leftover")
    enrich = snap.get("enrich_health") if isinstance(snap.get("enrich_health"), dict) else {}
    scanned_n = int(enrich.get("scanned") if enrich.get("scanned") is not None else snap.get("enrich_scanned") or 0)
    total_n = int(
        enrich.get("parse_total") if enrich.get("parse_total") is not None else snap.get("enrich_parse_total") or 0
    )
    if enrich.get("frozen"):
        parts.append(
            f"Entity/Annotation/Ontology Agents: enrich frozen at {scanned_n:,}/{total_n:,} — restart"
        )
    elif enrich.get("should_run"):
        parts.append("Entity/Annotation/Ontology Agents: enrich not scanning — start now")
    elif enrich.get("live"):
        parts.append(f"Entity scanned {scanned_n:,}/{total_n:,}")
    cpu_c = snap.get("cpu_temp_c")
    if gpu_temp is not None:
        parts.append(f"GPU {gpu_temp:.0f}°C{' abort-margin' if gpu_abort else ''}")
    if cpu_c is not None:
        parts.append(f"CPU {cpu_c:.0f}°C")
    if chassis.get("cpu_throttle_only") or chassis.get("cpu_warm_gpu_cool"):
        parts.append("CPU warm ≠ chassis abort — OCR Agent keeps draining")
    elif chassis.get("reason") and not chassis.get("ocr_may_run"):
        parts.append(str(chassis.get("reason")))
    extract = snap.get("extract_health") if isinstance(snap.get("extract_health"), dict) else {}
    if extract.get("stuck_restarting") or extract.get("should_stand_down"):
        parts.append(
            f"Extraction Agent: {int(extract.get('files_done') or 0):,}/"
            f"{int(extract.get('files_total') or 0):,} complete — do not resume"
        )
    windows = snap.get("windows_letters") or []
    missing = snap.get("missing_letters") or []
    if windows:
        parts.append("Windows " + ", ".join(windows))
    if missing:
        parts.append("Docker missing " + ", ".join(missing))
    elif snap.get("mounted_letters"):
        parts.append("Docker " + ", ".join(snap.get("mounted_letters") or []))
    lanes = snap.get("lanes") or {}
    if lanes:
        parts.append(
            f"GPU slots {lanes.get('gpu_slots_used') or 0}/"
            f"{lanes.get('gpu_slots_total') if lanes.get('gpu_slots_total') is not None else 1} used"
        )
        if lanes.get("cpu_heavy_reason"):
            parts.append(f"CPU-heavy={lanes.get('cpu_heavy_reason')}")
    return "Observe: " + "; ".join(parts)


def decide_huddle_actions(db, job_id: str, snap: dict[str, Any], *, gpu_abort: bool) -> list[dict[str, Any]]:
    """Performance + Observe agree which independent lanes Repair should start."""
    from app.services.job_control import extraction_is_stale, pipeline_is_stale
    from app.services.pipeline_supervisor import (
        _is_auto_resumable_pause,
        _should_redispatch,
        _stall_resume_sec,
    )

    row = snap.get("row")
    if not row or snap.get("stop_requested"):
        return []
    if snap.get("client_upload_pending"):
        return []
    status = snap.get("status") or ""
    settings = get_settings()
    stale_sec = _stall_resume_sec()
    actions: list[dict[str, Any]] = []

    extract_unfinished = (
        snap["files_total"] > 0
        and snap["files_done"] < snap["files_total"]
        and status in ("indexing", "paused", "failed")
    )
    from app.services.agent_duties import extract_agent_health

    extract_health = extract_agent_health(snap)
    extract_live = bool(extract_health["live"])
    if extract_health["complete"] or extract_health["should_stand_down"]:
        pass
    elif extract_live:
        pass
    elif extract_health["should_run"] or (
        (status in ("processing", "building_disk") and not extract_health["complete"])
        or extract_unfinished
        or (status == "paused" and "stalled" in (row.get("error") or "").lower())
    ):
        if extract_health["should_run"] or (
            extraction_is_stale(row, threshold_sec=stale_sec)
            or status in {"paused", "failed"}
            or (extract_unfinished and extraction_is_stale(row, threshold_sec=stale_sec))
        ):
            if _should_redispatch(db, job_id, "extract_agent", row, stale_threshold=stale_sec):
                actions.append(
                    {
                        "agent_id": "extract_agent",
                        "action": "resume_extraction",
                        "reason": (
                            f"Extract unfinished ({snap['files_done']:,}/{snap['files_total']:,})"
                            if snap.get("files_total")
                            else "Mobile extract never started — resume copy from payload ZIPs"
                        ),
                    }
                )

    if (
        status == "disk_ready"
        and (row.get("extracted_disk_uri") or snap["files_done"] > 0)
        and snap["artifact_n"] <= 0
        and _should_redispatch(db, job_id, "materialize_agent", row, stale_threshold=stale_sec)
    ):
        actions.append(
            {
                "agent_id": "materialize_agent",
                "action": "start_phase3",
                "reason": "Extract finished — materialize never started",
            }
        )

    parse_statuses = (
        "indexing",
        "indexed",
        "parsed",
        "artifacts_registered",
        "processing",
        "building_disk",
    )
    if (
        snap["parse_pending"] > 0
        and status in parse_statuses
        and _should_redispatch(db, job_id, "parse_agent", row, stale_threshold=stale_sec, within_sec=45.0)
        and (pipeline_is_stale(row, threshold_sec=stale_sec) or snap["parse_pending"] >= 50)
    ):
        actions.append(
            {
                "agent_id": "parse_agent",
                "action": "parse_drain",
                "reason": f"Parse pending ({snap['parse_pending']:,} forensic files)",
            }
        )

    ocr_statuses = parse_statuses + ("extracting",)
    ocr_left = int(snap.get("ocr_pending") or 0) + int(snap.get("ocr_unfinished") or 0)
    if (
        ocr_left > 0
        and status in ocr_statuses
        and settings.ocr_enabled
        and _should_redispatch(db, job_id, "ocr_agent", row, stale_threshold=stale_sec, within_sec=45.0)
    ):
        n = int(snap.get("ocr_pending") or 0) or int(snap.get("ocr_unfinished") or 0)
        actions.append(
            {
                "agent_id": "ocr_agent",
                "action": "ocr_drain",
                "reason": f"OCR pending ({n:,} documents) — GPU if free",
            }
        )

    embed_on = bool(getattr(settings, "rag_embedding_enabled", False))
    rag_statuses = (
        "indexing",
        "indexed",
        "extracted",
        "disk_ready",
        "parsed",
        "artifacts_registered",
        "paused",
    )
    if (
        embed_on
        and snap["rag_remaining"] > 0
        and status in rag_statuses
        and not gpu_abort
        and _should_redispatch(db, job_id, "rag_agent", row, stale_threshold=stale_sec, within_sec=45.0)
    ):
        actions.append(
            {
                "agent_id": "rag_agent",
                "action": "resume_rag",
                "reason": (
                    f"RAG embedding ({snap['chunk_n']:,} chunks, "
                    f"{snap['rag_remaining']:,} artifacts left) — independent of OCR"
                ),
            }
        )

    inv = snap.get("inventory") or {}
    artifacts_ready = False
    try:
        from app.services.catalog_artifact_runner import artifacts_ready_for_inventory

        artifacts_ready, _wait_reason = artifacts_ready_for_inventory(db, job_id)
    except Exception:
        artifacts_ready = False
    if (
        artifacts_ready
        and int(inv.get("total") or 0) > 0
        and not inv.get("done")
        and not snap.get("inventory_inflight")
        and status in ("indexing", "indexed", "parsed", "artifacts_registered")
        and _should_redispatch(db, job_id, "inventory_agent", row, stale_threshold=stale_sec, within_sec=45.0)
    ):
        actions.append(
            {
                "agent_id": "inventory_agent",
                "action": "artifact_inventory",
                "reason": f"Inventory pending ({inv.get('completed') or 0:,}/{inv.get('total') or 0:,}) — CPU lane",
            }
        )

    baseline_ready = (not embed_on) or snap["chunk_n"] >= 500 or snap["artifact_n"] > 0
    gs = snap.get("graph_status") or ""
    if (
        baseline_ready
        and status in ("indexing", "indexed")
        and gs not in ("ok", "skipped")
        and (gs not in ("queued", "syncing") or snap.get("graph_stale"))
        and _should_redispatch(db, job_id, "graph_agent", row, stale_threshold=stale_sec, within_sec=45.0)
    ):
        actions.append(
            {
                "agent_id": "graph_agent",
                "action": "graph_sync",
                "reason": "Neo4j graph sync — CPU lane, do not wait for leftover RAG",
            }
        )
    if (
        baseline_ready
        and gs in ("ok", "skipped")
        and not snap.get("enrich_done")
        and not snap.get("enrich_lock_held")
        and _should_redispatch(db, job_id, "rag_enrich_agent", row, stale_threshold=stale_sec, within_sec=45.0)
    ):
        enrich = snap.get("enrich_health") if isinstance(snap.get("enrich_health"), dict) else {}
        reason = (
            "Entity / annotation / ontology frozen — restart CPU lane"
            if enrich.get("frozen")
            else "Entity / annotation / ontology — CPU lane"
        )
        actions.append(
            {
                "agent_id": "rag_enrich_agent",
                "action": "rag_enrich",
                "reason": reason,
            }
        )

    if status == "paused" and _is_auto_resumable_pause(row) and not actions:
        # Always leave a paused thermal/stall job with at least CPU work or a resume.
        if snap["parse_pending"] > 0:
            actions.append(
                {
                    "agent_id": "parse_agent",
                    "action": "parse_drain",
                    "reason": "Resume parse after auto-resumable pause — no idle",
                }
            )
        elif snap["ocr_pending"] > 0:
            actions.append(
                {
                    "agent_id": "ocr_agent",
                    "action": "ocr_drain",
                    "reason": "Resume OCR after auto-resumable pause — GPU if free",
                }
            )
    return actions


def _persist_huddle(db, job_id: str, huddle: dict[str, Any]) -> None:
    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    pp = row.get("pipeline_progress") if row else {}
    if isinstance(pp, str):
        try:
            pp = json.loads(pp)
        except Exception:
            pp = {}
    if not isinstance(pp, dict):
        pp = {}
    orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    orch = dict(orch)
    orch["huddle"] = huddle
    pp["orchestration"] = orch
    try:
        execute(
            db,
            "UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id",
            {"pp": json.dumps(pp), "id": job_id},
        )
    except Exception as exc:
        log.debug("huddle persist skipped job=%s: %s", job_id, exc)


def _log_agent_blockers(
    db,
    job_id: str,
    snap: dict[str, Any],
    votes: list[dict[str, Any]],
    *,
    speak: bool,
) -> None:
    """Write who is running vs waiting so we can see which agent is blocking the pipeline."""
    waiting = [v for v in votes if v.get("want") == "wait"]
    running = [v for v in votes if v.get("want") in ("run", "idle")]
    done = [v for v in votes if v.get("want") == "done"]
    blockers: list[str] = []
    for v in waiting:
        reason = str(v.get("reason") or "")
        if "Download Agent" in reason:
            blockers.append("download_agent")
        elif "List Folder" in reason:
            blockers.append("list_folder_agent")
        elif "Get Segments" in reason or "Segments" in reason:
            blockers.append("segments_agent")
        elif "Extraction" in reason:
            blockers.append("extraction_agent")
        elif "Drive Mount" in reason:
            blockers.append("drive_mount_agent")
    blocker = blockers[0] if blockers else (running[0]["id"] if running else "none")
    wait_ids = ", ".join(v["id"] for v in waiting) or "none"
    run_ids = ", ".join(f"{v['id']}({v.get('reason', '')[:60]})" for v in running) or "none"
    recv = snap.get("download_received")
    exp = snap.get("download_expected")
    pending = bool(snap.get("client_upload_pending"))
    summary = (
        f"[Huddle] blocker={blocker}"
        + (f" receiving {recv}/{exp or '?'} parallelism={snap.get('download_parallelism') or 3}" if pending else "")
        + f" | waiting: {wait_ids}"
        + f" | working: {run_ids}"
        + f" | done: {len(done)} agent(s)"
    )
    log.info("huddle blockers job=%s %s", job_id, summary)
    if speak:
        write_disk_log(
            db,
            job_id,
            summary,
            stage="supervisor",
            metadata={
                "blocker": blocker,
                "waiting": [v["id"] for v in waiting],
                "working": [v["id"] for v in running],
                "done": [v["id"] for v in done],
                "download_pending": pending,
                "download_received": recv,
                "download_expected": exp,
                "votes": [
                    {"id": v.get("id"), "want": v.get("want"), "reason": v.get("reason"), "decision": v.get("decision")}
                    for v in votes
                ],
            },
        )
        for v in waiting:
            write_disk_log(
                db,
                job_id,
                f"[{v.get('id')}] wait — blocked: {v.get('reason')}",
                stage="supervisor",
                metadata={"agent_id": v.get("id"), "want": "wait", "blocker": blocker},
            )
        for v in running:
            write_disk_log(
                db,
                job_id,
                f"[{v.get('id')}] {v.get('want')} — {v.get('reason')}",
                stage="supervisor",
                metadata={"agent_id": v.get("id"), "want": v.get("want")},
            )


def _clear_auto_pause(db, job_id: str, row: dict | None) -> None:
    from app.services.pipeline_supervisor import _is_auto_resumable_pause

    if not row or (row.get("status") or "") != "paused":
        return
    if not _is_auto_resumable_pause(row):
        return
    execute(
        db,
        """UPDATE jobs SET status='indexing', error=NULL, stop_requested=FALSE, updated_at=NOW()
           WHERE id=:id AND stop_requested=FALSE""",
        {"id": job_id},
    )


def run_agent_huddle(db, job_id: str, *, schema_name: str) -> dict[str, Any]:
    """Observe reports, Performance plans, Repair starts every independent lane."""
    from app.services.performance_agent import apply_performance_advice
    from app.services.pipeline_supervisor import (
        _recent_supervisor_action,
        dispatch_stage_agent,
    )

    snap = observe_pipeline_snapshot(db, job_id)
    if not snap.get("row") or snap.get("stop_requested"):
        return {"status": "skipped", "reason": "stopped_or_missing", "job_id": job_id}
    if not snap.get("intake_started"):
        # Hard gate: no huddle, GPU/CPU planning, drive mount persistence, votes,
        # repair dispatch, or agent log spam before the examiner selects evidence.
        return {
            "status": "skipped",
            "reason": "awaiting_evidence_selection",
            "job_id": job_id,
        }

    mounted_now = list(snap.get("mounted_letters") or [])
    if mounted_now or snap.get("drives_ready"):
        try:
            from app.services.pipeline_orchestrator import persist_drive_mount_complete

            persist_drive_mount_complete(
                db,
                job_id,
                mounted=mounted_now,
                detail=(
                    "Drives already mounted ("
                    + (", ".join(mounted_now) or "host drives")
                    + ") — no remount"
                ),
            )
        except Exception as exc:
            log.debug("drive mount persist skipped job=%s: %s", job_id, exc)

    gpu_abort, gpu_temp = _gpu_at_abort()
    if gpu_temp is not None:
        snap["gpu_temp_c"] = gpu_temp
    try:
        from app.services.agent_duties import assess_chassis_for_ocr

        snap["chassis"] = assess_chassis_for_ocr(snap.get("gpu_temp_c"), snap.get("cpu_temp_c"))
    except Exception:
        snap.setdefault("chassis", {})
    observe_line = _observe_speech(snap, gpu_temp, gpu_abort)

    perf: dict[str, Any] = {}
    try:
        perf = apply_performance_advice(db, job_id) or {}
    except Exception as exc:
        log.debug("huddle performance skipped job=%s: %s", job_id, exc)
        perf = {"error": str(exc)[:160]}

    live = perf.get("live_plan") if isinstance(perf.get("live_plan"), dict) else {}
    if not isinstance(perf.get("lanes"), dict):
        perf["lanes"] = snap.get("lanes") or {}
    chassis = snap.get("chassis") if isinstance(snap.get("chassis"), dict) else {}
    perf["chassis"] = chassis
    lanes = perf.get("lanes") or {}
    gpu_total = int(lanes.get("gpu_slots_total") if lanes.get("gpu_slots_total") is not None else 1)
    gpu_slot_txt = (
        f"GPU {lanes.get('gpu_slots_used') or 0}/{gpu_total} slots"
        + (
            " — share OCR+RAG"
            if lanes.get("can_share_gpu")
            else " — thermal hold"
            if gpu_total == 0
            else " — one GPU job at a time"
            if gpu_total <= 1
            else ""
        )
    )
    chassis_txt = ""
    if chassis.get("cpu_throttle_only") or chassis.get("cpu_warm_gpu_cool"):
        chassis_txt = " — CPU warm, GPU cool, OCR Agent keeps draining"
    elif gpu_abort or chassis.get("too_hot"):
        chassis_txt = f" — {chassis.get('reason') or 'GPU abort margin, keep CPU lanes'}"
    perf_line = (
        "Performance: "
        f"parallel={perf.get('allow_parallel')} "
        f"parse={live.get('parse_workers') or '?'} "
        f"OCR batch={live.get('ocr_batch_limit') or '?'} "
        f"{gpu_slot_txt}"
        + chassis_txt
    )

    from app.services.action_agents import (
        collect_action_votes,
        performance_arbitrate,
        votes_to_dispatch_recs,
    )

    votes: list[dict[str, Any]] = []
    try:
        votes = collect_action_votes(snap)
        performance_arbitrate(votes, perf, gpu_abort=gpu_abort)
        recs = votes_to_dispatch_recs(votes)
    except Exception as exc:
        log.warning("action-agent votes failed job=%s: %s", job_id, exc)
        recs = []
    if not recs and not snap.get("client_upload_pending"):
        recs = decide_huddle_actions(db, job_id, snap, gpu_abort=gpu_abort)
    else:
        # Votes often only emit rag_enrich. Always keep inventory/parse CPU lanes
        # from decide_huddle_actions so iosagent cataloging cannot stall at 1%.
        extra = decide_huddle_actions(db, job_id, snap, gpu_abort=gpu_abort)
        seen = {(r.get("agent_id"), r.get("action")) for r in recs}
        for rec in extra:
            key = (rec.get("agent_id"), rec.get("action"))
            if key not in seen:
                recs.append(rec)
                seen.add(key)
    _clear_auto_pause(db, job_id, snap.get("row"))

    dispatched: list[dict[str, Any]] = []
    for rec in recs:
        if rec.get("action") == "mount_drives" and (mounted_now or snap.get("drives_ready")):
            dispatched.append(
                {
                    "agent_id": rec.get("agent_id"),
                    "action": rec.get("action"),
                    "status": "already_complete",
                }
            )
            continue
        if rec.get("action") in _GPU_ACTIONS and gpu_abort:
            continue
        if rec.get("action") == "resume_extraction":
            from app.services.agent_duties import extract_agent_health

            health = extract_agent_health(snap)
            if health["complete"] or health["live"] or health["should_stand_down"]:
                if health.get("stuck_restarting"):
                    from app.services.disk import restore_status_if_extract_complete

                    restored = restore_status_if_extract_complete(db, job_id)
                    if restored:
                        snap["status"] = restored
                    if snap.get("lanes", {}).get("extract_lock"):
                        try:
                            from app.services.job_locks import force_release_job_lock

                            force_release_job_lock("extract", job_id)
                        except Exception:
                            pass
                dispatched.append(
                    {
                        "agent_id": rec.get("agent_id"),
                        "action": rec.get("action"),
                        "status": "already_complete" if health["complete"] else "already_running",
                    }
                )
                continue
        try:
            result = dispatch_stage_agent(db, job_id, schema_name=schema_name, recommendation=rec)
            dispatched.append({"agent_id": rec.get("agent_id"), "action": rec.get("action"), **result})
        except Exception as exc:
            log.warning("huddle repair failed job=%s rec=%s: %s", job_id, rec.get("action"), exc)
            dispatched.append({"agent_id": rec.get("agent_id"), "status": "error", "error": str(exc)[:160]})

    queued = [
        f"{d.get('agent_id')}:{d.get('action')}"
        for d in dispatched
        if d.get("status") not in ("error", "already_running", "already_complete", "deferred")
    ]
    worker_bits = [
        f"{d.get('action')}×{int(d.get('workers') or 0)}"
        for d in dispatched
        if int(d.get("workers") or 0) > 1
    ]
    if queued:
        extra = f" ({', '.join(worker_bits)})" if worker_bits else ""
        repair_line = "Repair: queued " + ", ".join(queued) + extra + " — started workers, no pause"
    elif gpu_abort and any(r.get("action") in _GPU_ACTIONS for r in recs):
        repair_line = "Repair: GPU at abort margin — CPU lanes stay up, GPU retries next huddle"
    else:
        repair_line = "Repair: every requested lane already running — no pause"

    go_votes = [v["id"] for v in votes if v.get("decision") == "go"]
    hold_votes = [v["id"] for v in votes if v.get("decision") == "hold"]
    try:
        from app.services.pipeline_orchestrator import merge_orchestration_into_progress

        merge_orchestration_into_progress(db, job_id)
    except Exception:
        pass
    huddle = {
        "observe": observe_line,
        "performance": perf_line,
        "repair": repair_line,
        "queued": queued,
        "lanes": lanes,
        "gpu_temp_c": gpu_temp,
        "gpu_abort_margin": gpu_abort,
        "ocr_health": snap.get("ocr_health") or {},
        "chassis": chassis,
        "votes": votes,
        "approved": go_votes,
        "held": hold_votes,
        "drives_ready": bool(snap.get("drives_ready") or mounted_now),
        "mounted_letters": mounted_now,
    }
    speak = not _recent_supervisor_action(db, job_id, "Agent huddle", within_sec=40.0)
    _log_agent_blockers(db, job_id, snap, votes, speak=speak)
    if speak:
        write_disk_log(
            db,
            job_id,
            "[Agent huddle] Observe, Performance, and Repair conferred — keep every lane moving",
            stage="supervisor",
            metadata={"huddle": huddle},
        )
        write_disk_log(
            db,
            job_id,
            f"[Agent huddle] {observe_line}",
            stage="observe",
            metadata={"huddle": huddle},
        )
        write_disk_log(
            db,
            job_id,
            f"[Agent huddle] {perf_line}",
            stage="performance",
            metadata={"huddle": huddle},
        )
        write_disk_log(
            db,
            job_id,
            f"[Agent huddle] {repair_line}",
            stage="repair",
            metadata={"huddle": huddle},
        )
        record_heal_event(
            db,
            job_id,
            agent="huddle",
            issue_code="agent_huddle",
            issue_detail=observe_line,
            stage="orchestration",
            remedy_code="keep_lanes_moving",
            remedy_detail=f"{perf_line} | {repair_line}",
            status="resolved",
            metadata=huddle,
        )
    _persist_huddle(db, job_id, huddle)
    try:
        db.commit()
    except Exception:
        pass
    log.info("huddle job=%s queued=%s gpu_abort=%s", job_id, queued, gpu_abort)
    return {"status": "ok", "job_id": job_id, "queued": queued, "huddle": huddle}
