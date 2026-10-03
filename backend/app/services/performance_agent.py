"""Performance agent — CPU/GPU parallelism, query indexes, live plan broadcast."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text

from app.config import get_settings
from app.db.sql_helpers import execute, fetchone
from app.services.disk_build_log import write_disk_log
from app.services.pipeline_heal import record_heal_event

log = logging.getLogger("performance_agent")

_SAFE_PARALLEL_AFTER_BASELINE = frozenset(
    {
        "parse_agent",
        "ocr_agent",
        "rag_agent",
        "inventory_agent",
        "graph_agent",
        "rag_enrich_agent",
        "drive_mount_agent",
        "list_folder_agent",
        "segments_agent",
        "virtual_disk_agent",
        "extraction_agent",
        "materialize_agent",
        "chunk_agent",
        "embed_agent",
        "entity_agent",
        "neo4j_agent",
        "annotation_agent",
        "ontology_agent",
        "artifacts_agent",
    }
)

_INDEXES_READY: set[str] = set()

# Fast pending-work and lookup indexes. IF NOT EXISTS + savepoint so a missing
# column never aborts the supervisor transaction.
_PIPELINE_INDEXES: tuple[tuple[str, str], ...] = (
    (
        "ix_job_artifacts_job_parse_pending",
        "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_parse_pending "
        "ON job_artifacts (job_id) WHERE parse_status = 'pending'",
    ),
    (
        "ix_job_artifacts_job_ocr_pending",
        "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_ocr_pending "
        "ON job_artifacts (job_id) WHERE ocr_status = 'pending'",
    ),
    (
        "ix_job_artifacts_job_parse_status",
        "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_parse_status "
        "ON job_artifacts (job_id, parse_status)",
    ),
    (
        "ix_job_artifacts_job_ocr_status",
        "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_ocr_status "
        "ON job_artifacts (job_id, ocr_status)",
    ),
    (
        "ix_job_artifacts_job_id_id",
        "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_id_id "
        "ON job_artifacts (job_id, id)",
    ),
    (
        "ix_artifact_parse_results_artifact_created",
        "CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact_created "
        "ON artifact_parse_results (job_artifact_id, created_at DESC)",
    ),
    (
        "ix_artifact_parse_results_artifact_id",
        "CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact_id "
        "ON artifact_parse_results (job_artifact_id, id)",
    ),
    (
        "ix_ocr_results_artifact_created",
        "CREATE INDEX IF NOT EXISTS ix_ocr_results_artifact_created "
        "ON ocr_results (job_artifact_id, created_at DESC)",
    ),
    (
        "ix_rag_chunks_job_path_evidence",
        "CREATE INDEX IF NOT EXISTS ix_rag_chunks_job_path_evidence "
        "ON rag_chunks (job_id, file_path) "
        "WHERE chunk_type IN ('evidence','evidence_skip')",
    ),
    (
        "ix_rag_chunks_job_artifact",
        "CREATE INDEX IF NOT EXISTS ix_rag_chunks_job_artifact "
        "ON rag_chunks (job_id, artifact_id) WHERE artifact_id IS NOT NULL",
    ),
    (
        "ix_disk_build_logs_job_stage",
        "CREATE INDEX IF NOT EXISTS ix_disk_build_logs_job_stage "
        "ON disk_build_logs (job_id, stage, timestamp DESC)",
    ),
)


def ensure_performance_indexes(db) -> dict[str, Any]:
    """Create query indexes that speed parse/OCR/RAG pending scans. Idempotent."""
    schema = "public"
    try:
        row = fetchone(db, "SELECT current_schema() AS s", {})
        schema = str((row or {}).get("s") or "public")
    except Exception:
        schema = "public"
    if schema in _INDEXES_READY:
        return {"schema": schema, "status": "ready", "created": []}

    created: list[str] = []
    skipped: list[str] = []
    for i, (name, sql) in enumerate(_PIPELINE_INDEXES):
        sp = f"perf_idx_{i}"
        try:
            db.execute(text(f"SAVEPOINT {sp}"))
            execute(db, sql)
            db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            created.append(name)
        except Exception as exc:
            skipped.append(name)
            log.debug("performance index %s skipped: %s", name, exc)
            try:
                db.execute(text(f"ROLLBACK TO SAVEPOINT {sp}"))
            except Exception:
                pass
    _INDEXES_READY.add(schema)
    log.info(
        "Performance indexes schema=%s created_or_exist=%s skipped=%s",
        schema,
        len(created),
        skipped,
    )
    return {"schema": schema, "status": "applied", "created": created, "skipped": skipped}


def _gpu_snapshot() -> dict[str, Any]:
    settings = get_settings()
    out: dict[str, Any] = {"available": False, "temperature_c": None, "too_hot": False}
    if not settings.gpu_thermal_enabled:
        return out
    try:
        from app.services.gpu_thermal import get_gpu_stats

        stats = get_gpu_stats()
        out["available"] = bool(stats.available)
        out["temperature_c"] = stats.temperature_c
        abort_c = int(getattr(settings, "gpu_thermal_abort_c", 94) or 94)
        if stats.available and stats.temperature_c is not None:
            out["too_hot"] = stats.temperature_c >= abort_c
        try:
            from app.services.agent_duties import assess_chassis_for_ocr
            from app.services.host_capacity import probe_host

            cpu_c = probe_host().cpu_temp_c
            out["cpu_temperature_c"] = cpu_c
            chassis = assess_chassis_for_ocr(out.get("temperature_c"), cpu_c)
            out["chassis"] = chassis
            out["too_hot"] = bool(chassis.get("too_hot"))
        except Exception:
            pass
    except Exception as exc:
        out["error"] = str(exc)[:200]
    return out


def apply_performance_advice(db, job_id: str) -> dict[str, Any]:
    """Retune capacity, build/broadcast live plan, persist orchestration flags."""
    from app.services.pipeline_orchestrator import pipeline_intake_started

    gate_row = fetchone(
        db,
        """SELECT status, disk_source, segment_readiness, extracted_disk_uri,
                  files_total, files_extracted
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    if not pipeline_intake_started(gate_row):
        return {
            "status": "skipped",
            "reason": "awaiting_evidence_selection",
            "job_id": job_id,
            "live_plan": {},
            "lanes": {},
        }

    settings = get_settings()
    policy_mode = str(getattr(settings, "perf_policy_mode", "throughput") or "throughput").strip().lower()
    strict_sequential = bool(getattr(settings, "pipeline_sequential_agents", False)) and policy_mode in {
        "sequential", "respect_env"
    }
    capacity: dict[str, Any] = {}
    try:
        from app.services.host_capacity import apply_dynamic_performance

        plan_cap = apply_dynamic_performance()
        capacity = plan_cap.to_dict() if hasattr(plan_cap, "to_dict") else {}
    except Exception as exc:
        capacity = {"error": str(exc)[:200]}

    from app.services.perf_broadcast import publish_live_plan
    from app.services.perf_policy import build_live_plan, confirm_plan_with_llm

    indexes = ensure_performance_indexes(db)
    gpu = _gpu_snapshot()
    lanes: dict[str, Any] = {}
    try:
        from app.services.job_locks import inspect_process_lanes

        lanes = inspect_process_lanes(job_id)
    except Exception as exc:
        lanes = {"error": str(exc)[:160]}
    live = build_live_plan(db, job_id, capacity=capacity)
    live["lanes"] = lanes
    resource_semaphores: dict[str, Any] = {}
    try:
        from app.services.adaptive_semaphore import semaphore_snapshot

        resource_semaphores = {
            "gpu": semaphore_snapshot(
                "gpu",
                requested_limit=max(int(getattr(settings, "gpu_heavy_max_concurrent", 1) or 1), 1),
            ),
            "cpu_heavy": semaphore_snapshot(
                "cpu_heavy",
                requested_limit=max(int(getattr(settings, "max_concurrent_disk_builds", 1) or 1), 1),
            ),
        }
        live["resource_semaphores"] = resource_semaphores
    except Exception as exc:
        resource_semaphores = {"error": str(exc)[:160]}
    if lanes.get("can_share_gpu"):
        live.setdefault("notes", [])
        if isinstance(live.get("notes"), list):
            live["notes"].append(
                f"GPU share OK — {lanes.get('gpu_slots_free')}/{lanes.get('gpu_slots_total')} slots free"
            )
    if not strict_sequential:
        live["allow_parallel"] = True
        extra = set(_SAFE_PARALLEL_AFTER_BASELINE)
        if gpu.get("too_hot") or live.get("too_hot"):
            extra -= {"rag_agent"}
            live["defer_background_rag"] = True
        else:
            live["defer_background_rag"] = False
        live["safe_parallel_agents"] = sorted(set(live.get("safe_parallel_agents") or []) | extra)
        live.setdefault("notes", [])
        if isinstance(live.get("notes"), list):
            live["notes"].append(
                "Performance agent: independent GPU slots + extra CPU parse/OCR workers"
            )
    try:
        live = confirm_plan_with_llm(live)
    except Exception as exc:
        log.debug("LLM confirm skipped: %s", exc)

    published = publish_live_plan(live, ttl_sec=300)

    allow_parallel = bool(live.get("allow_parallel"))
    safe_parallel = list(live.get("safe_parallel_agents") or [])
    if gpu.get("too_hot") or live.get("too_hot"):
        # v1.5: thermal pressure must never re-enable DB/IO parallelism when the
        # deployment explicitly asks for a responsive stage-aware pipeline.
        if strict_sequential:
            allow_parallel = False
            safe_parallel = []
            remedy_code = "defer_rag_thermal_sequential"
            remedy_detail = (
                f"GPU at {live.get('gpu_temp_c') or gpu.get('temperature_c')}°C — "
                "pause/throttle the active stage; keep other heavy agents serialized "
                f"(abort≥{getattr(settings, 'gpu_thermal_abort_c', 78)}°C)"
            )
        else:
            allow_parallel = True
            if not safe_parallel:
                safe_parallel = sorted({"inventory_agent", "parse_agent", "graph_agent"})
            else:
                safe_parallel = [
                    a for a in safe_parallel if a in {"inventory_agent", "parse_agent", "graph_agent"}
                ] or sorted({"inventory_agent", "parse_agent", "graph_agent"})
            remedy_code = "defer_rag_thermal"
            remedy_detail = (
                f"GPU at {live.get('gpu_temp_c') or gpu.get('temperature_c')}°C — "
                f"throttle embeds / prefer inventory while cooling "
                f"(abort≥{getattr(settings, 'gpu_thermal_abort_c', 78)}°C)"
            )
    elif allow_parallel:
        remedy_code = "allow_parallel_post_baseline"
        remedy_detail = (
            f"Baseline {live.get('baseline_chunks', 0):,} chunks — parallel "
            f"graph/inventory/parse; RAG batch={live.get('rag_batch_size')} "
            f"OCR={live.get('ocr_batch_limit')} inv={live.get('inventory_workers')} "
            f"mobile_extract={live.get('extract_mobile_workers')}"
        )
    else:
        remedy_code = "capacity_tuned"
        remedy_detail = (
            f"Profile {live.get('profile')} pace={live.get('pace')} — "
            f"RAG batch={live.get('rag_batch_size')} OCR={live.get('ocr_batch_limit')} "
            f"inv={live.get('inventory_workers')} (published={published})"
        )

    if live.get("llm_confirmed"):
        remedy_detail += " · LLM confirmed"
        remedy_code = f"{remedy_code}_llm"

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
    orch["performance"] = {
        "allow_parallel": allow_parallel,
        "safe_parallel_agents": safe_parallel,
        "lanes": lanes,
        "resource_semaphores": resource_semaphores,
        "gpu": gpu,
        "live_plan": {
            k: live.get(k)
            for k in (
                "profile",
                "pace",
                "gpu_temp_c",
                "rag_batch_size",
                "ocr_batch_limit",
                "inventory_workers",
                "extract_mobile_workers",
                "parse_workers",
                "too_hot",
                "llm_confirmed",
                "notes",
            )
        },
        "capacity": {
            k: capacity.get(k)
            for k in ("profile", "notes")
            if isinstance(capacity, dict) and k in capacity
        }
        or capacity,
        "remedy_code": remedy_code,
        "published": published,
        "indexes": {"status": indexes.get("status"), "ready": len(indexes.get("created") or [])},
    }
    pp["orchestration"] = orch
    try:
        execute(
            db,
            # Do not bump jobs.updated_at — that heartbeat is used to detect extract/pipeline
            # stalls. Performance advice used to refresh it every ~45s and block auto-resume.
            "UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id",
            {"pp": json.dumps(pp), "id": job_id},
        )
    except Exception as exc:
        log.warning("performance orch update failed job=%s: %s", job_id, exc)

    record_heal_event(
        db,
        job_id,
        agent="performance",
        issue_code="performance_advise",
        issue_detail="Live performance plan for extract/RAG/artifacts",
        stage="orchestration",
        remedy_code=remedy_code,
        remedy_detail=remedy_detail,
        status="resolved",
        metadata={
            "gpu": gpu,
            "allow_parallel": allow_parallel,
            "live_plan": orch["performance"].get("live_plan"),
            "indexes": indexes,
        },
    )
    idx_note = ""
    if indexes.get("status") == "applied":
        idx_note = f" · indexes {len(indexes.get('created') or [])} ready"
    write_disk_log(
        db,
        job_id,
        f"[Performance agent] {remedy_detail}{idx_note}",
        stage="performance",
        metadata={
            "remedy_code": remedy_code,
            "allow_parallel": allow_parallel,
            "gpu": gpu,
            "live_plan": live,
            "indexes": indexes,
        },
    )
    return {
        "allow_parallel": allow_parallel,
        "remedy_code": remedy_code,
        "gpu": gpu,
        "chassis": gpu.get("chassis") if isinstance(gpu, dict) else {},
        "lanes": lanes,
        "live_plan": live,
        "safe_parallel_agents": safe_parallel,
        "indexes": indexes,
    }


def performance_allows_agent(db, job_id: str, agent_id: str) -> bool:
    """True when Performance agent has enabled parallel for this agent."""
    settings = get_settings()
    mode = str(getattr(settings, "perf_policy_mode", "throughput") or "throughput").strip().lower()
    if bool(getattr(settings, "pipeline_sequential_agents", False)) and mode in {"sequential", "respect_env"}:
        return False
    # Prefer fresh Redis plan (works even if DB orch flag is stale).
    try:
        from app.services.perf_broadcast import get_live_perf_plan

        plan = get_live_perf_plan()
        if plan and plan.get("allow_parallel"):
            allowed = set(plan.get("safe_parallel_agents") or _SAFE_PARALLEL_AFTER_BASELINE)
            from app.forensic_common.pipeline_routing import normalize_stage_agent_id

            return normalize_stage_agent_id(agent_id) in allowed or agent_id in allowed
    except Exception:
        pass

    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    pp = row.get("pipeline_progress") if row else {}
    if isinstance(pp, str):
        try:
            pp = json.loads(pp)
        except Exception:
            pp = {}
    orch = (pp or {}).get("orchestration") if isinstance(pp, dict) else {}
    perf = (orch or {}).get("performance") if isinstance(orch, dict) else {}
    if not isinstance(perf, dict) or not perf.get("allow_parallel"):
        return False
    allowed = set(perf.get("safe_parallel_agents") or [])
    from app.forensic_common.pipeline_routing import normalize_stage_agent_id

    return normalize_stage_agent_id(agent_id) in allowed or agent_id in allowed
