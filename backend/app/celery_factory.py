"""Celery apps scoped to one Aetheris product."""

from __future__ import annotations

import os
import tempfile

from celery import Celery

from app.config import get_settings
from app.service_identity import (
    FORENSIC,
    MOBILE_ANDROID,
    MOBILE_EXTRACT,
    MOBILE_IOS,
    MOBILE_SERVICES,
    VULN,
    current_service,
)

FORENSIC_ROUTES = {
    "app.tasks.build_extracted_disk_task": {"queue": "disk-build"},
    "app.tasks.rag_index_task": {"queue": "rag-index"},
    "app.tasks.phase3_pipeline_task": {"queue": "disk-parse"},
    "app.tasks.phase3_shard_task": {"queue": "disk-parse"},
    "app.tasks.phase3_finalize_task": {"queue": "disk-parse"},
    "app.tasks.parse_drain_task": {"queue": "disk-parse"},
    "app.tasks.parse_shard_task": {"queue": "disk-parse"},
    "app.tasks.parse_bucket_task": {"queue": "disk-parse"},
    "app.tasks.rag_append_task": {"queue": "rag-index"},
    "app.tasks.ocr_drain_task": {"queue": "ocr"},
    "app.tasks.ocr_bucket_task": {"queue": "ocr"},
    "app.tasks.axiom_artifact_inventory_task": {"queue": "disk-parse"},
    "app.tasks.graph_sync_task": {"queue": "agent-orchestration"},
    "app.tasks.rag_enrich_task": {"queue": "disk-parse"},
    "app.tasks.report_gen_task": {"queue": "report-gen"},
    "app.tasks.forensic_agent_chat_task": {"queue": "agent-orchestration"},
    "app.tasks.pipeline_supervisor_task": {"queue": "agent-orchestration"},
}

def _mobile_routes(prefix: str) -> dict[str, dict[str, str]]:
    build = f"{prefix}-build"
    parse = f"{prefix}-parse"
    rag = f"{prefix}-rag"
    ocr = f"{prefix}-ocr"
    report = f"{prefix}-report"
    return {
        "app.tasks.build_extracted_mobile_task": {"queue": build},
        "app.tasks.parse_drain_mobile_task": {"queue": parse},
        "app.tasks.parse_drain_task": {"queue": parse},
        "app.tasks.parse_shard_task": {"queue": parse},
        "app.tasks.parse_bucket_task": {"queue": parse},
        "app.tasks.axiom_artifact_inventory_mobile_task": {"queue": parse},
        "app.tasks.mobile_analysis_task": {"queue": parse},
        "app.tasks.phase3_pipeline_task": {"queue": parse},
        "app.tasks.phase3_finalize_task": {"queue": parse},
        "app.tasks.phase3_shard_task": {"queue": parse},
        "app.tasks.rag_index_task": {"queue": rag},
        "app.tasks.rag_append_task": {"queue": rag},
        "app.tasks.ocr_drain_task": {"queue": ocr},
        "app.tasks.ocr_bucket_task": {"queue": ocr},
        "app.tasks.graph_sync_task": {"queue": parse},
        "app.tasks.rag_enrich_task": {"queue": parse},
        "app.tasks.pipeline_supervisor_task": {"queue": build},
        "app.tasks.report_gen_task": {"queue": report},
    }


# Legacy mobile-extract queue names are retained so upgrades can drain old
# jobs without sharing queues with the new Android/iOS products.
MOBILE_ROUTES = {
    "app.tasks.build_extracted_mobile_task": {"queue": "mobile-build"},
    "app.tasks.parse_drain_mobile_task": {"queue": "mobile-build"},
    "app.tasks.parse_drain_task": {"queue": "mobile-build"},
    "app.tasks.parse_shard_task": {"queue": "mobile-build"},
    "app.tasks.parse_bucket_task": {"queue": "mobile-build"},
    "app.tasks.axiom_artifact_inventory_mobile_task": {"queue": "mobile-build"},
    "app.tasks.mobile_analysis_task": {"queue": "mobile-build"},
    "app.tasks.phase3_pipeline_task": {"queue": "mobile-build"},
    "app.tasks.phase3_finalize_task": {"queue": "mobile-build"},
    "app.tasks.phase3_shard_task": {"queue": "mobile-build"},
    "app.tasks.rag_index_task": {"queue": "rag-index"},
    "app.tasks.rag_append_task": {"queue": "rag-index"},
    "app.tasks.ocr_drain_task": {"queue": "ocr"},
    "app.tasks.ocr_bucket_task": {"queue": "ocr"},
    "app.tasks.graph_sync_task": {"queue": "mobile-build"},
    "app.tasks.rag_enrich_task": {"queue": "mobile-build"},
    "app.tasks.pipeline_supervisor_task": {"queue": "mobile-build"},
    "app.tasks.report_gen_task": {"queue": "mobile-build"},
}
ANDROID_ROUTES = _mobile_routes("android")
IOS_ROUTES = _mobile_routes("ios")

VULN_ROUTES = {
    "app.tasks.nessus_scan_sync_task": {"queue": "nessus-sync"},
    "app.tasks.vuln_brd_maintenance_task": {"queue": "nessus-sync"},
    "app.tasks.pentest_job_task": {"queue": "nessus-sync"},
}

_COMMON = {
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],
    "task_track_started": True,
    "task_acks_late": True,
    "worker_prefetch_multiplier": 1,
    "broker_connection_retry_on_startup": True,
    "broker_connection_retry": True,
    "broker_connection_max_retries": 100,
    "broker_transport_options": {"visibility_timeout": 3600 * 24 * 14},
    "task_default_queue": "default",
}


def _probe_perf() -> None:
    try:
        from app.services.host_capacity import apply_dynamic_performance
        from app.services.perf_broadcast import publish_live_plan
        from app.services.perf_policy import build_live_plan

        apply_dynamic_performance()
        publish_live_plan(build_live_plan())
    except Exception:
        pass


def create_celery(service: str | None = None) -> Celery:
    svc = service or current_service()
    _probe_perf()
    settings = get_settings()
    celery = Celery(f"aetheris-{svc}", broker=settings.redis_url, backend=settings.redis_url)
    routes = {
        FORENSIC: FORENSIC_ROUTES,
        MOBILE_ANDROID: ANDROID_ROUTES,
        MOBILE_IOS: IOS_ROUTES,
        MOBILE_EXTRACT: MOBILE_ROUTES,
        VULN: VULN_ROUTES,
    }.get(svc, FORENSIC_ROUTES)
    celery.conf.update({**_COMMON, "task_routes": routes})
    # gdbm cannot lock celerybeat-schedule on a Windows Docker bind-mount (/app).
    # Keep the file on the container tmpfs so Beat survives worker restarts.
    celery.conf.beat_schedule_filename = os.path.join(
        tempfile.gettempdir(), f"celerybeat-schedule-{svc}"
    )
    if svc == FORENSIC or svc in MOBILE_SERVICES:
        celery.conf.beat_schedule = {
            "pipeline-supervisor-watchdog": {
                "task": "app.tasks.pipeline_supervisor_task",
                "schedule": max(float(settings.pipeline_supervisor_interval_sec or 30.0), 20.0),
                "kwargs": {},
            },
        }
    return celery
