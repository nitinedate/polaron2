"""One agent per pipeline action. They vote each huddle; Performance decides."""

from __future__ import annotations

import re
from typing import Any

# Chair + advisors — they do not extract/parse themselves.
COUNCIL_AGENTS: tuple[dict[str, Any], ...] = (
    {
        "id": "pipeline_supervisor",
        "name": "Pipeline Supervisor",
        "role": "council",
        "action": "Open the huddle every 30s and record the minutes",
        "lane": "control",
        "consults": ["observe_agent", "performance_agent", "repair_agent"],
    },
    {
        "id": "observe_agent",
        "name": "Observe Agent",
        "role": "council",
        "action": (
            "Report pending work, OCR unfinished vs eligible (never treat skipped files as leftover), "
            "and CPU vs GPU heat meaning"
        ),
        "lane": "control",
        "consults": ["performance_agent", "repair_agent"],
    },
    {
        "id": "performance_agent",
        "name": "Performance Agent",
        "role": "council",
        "action": (
            "Decide who may run. Chassis abort is GPU pause/abort or CPU pause — "
            "never treat CPU throttle (~80°C) with a cool GPU as too hot"
        ),
        "lane": "control",
        "consults": ["observe_agent", "repair_agent"],
    },
    {
        "id": "repair_agent",
        "name": "Repair Agent",
        "role": "council",
        "action": (
            "Start every lane Performance approved. Do not re-queue ocr_drain after OCR Agent "
            "stands down; do not re-queue resume_extraction after Extraction Agent stands down; "
            "start entity/annotation/ontology instead"
        ),
        "lane": "control",
        "consults": ["observe_agent", "performance_agent"],
    },
)

# One agent per process action (UI cards). Sibling agents may share a worker task.
ACTION_AGENTS: tuple[dict[str, Any], ...] = (
    {
        "id": "drive_mount_agent",
        "name": "Drive Mount Agent",
        "role": "action",
        "action": "Find every attached drive letter and remount it in Docker",
        "lane": "io",
        "queue": "agent-orchestration",
        "dispatch_agent": "drive_mount_agent",
        "dispatch_action": "mount_drives",
        "consults": ["list_folder_agent", "performance_agent", "observe_agent"],
    },
    {
        "id": "download_agent",
        "name": "Download Agent",
        "role": "action",
        "action": "Receive E01/EWF segments from the client, 5 at a time, then signal other agents",
        "lane": "io",
        "queue": "agent-orchestration",
        "dispatch_agent": None,
        "dispatch_action": None,
        "consults": ["list_folder_agent", "performance_agent", "observe_agent"],
    },
    {
        "id": "iosagent",
        "name": "iOS Agent",
        "role": "action",
        "action": (
            "Own iPhone/iPad USB collection, extract, parse, and RAG. "
            "Refuse Android work."
        ),
        "lane": "io",
        "queue": "ios-build",
        "dispatch_agent": "extract_agent",
        "dispatch_action": "resume_extraction",
        "consults": ["androidagent", "performance_agent", "observe_agent"],
    },
    {
        "id": "androidagent",
        "name": "Android Agent",
        "role": "action",
        "action": (
            "Own Android USB/MTP/ADB collection, extract, parse, and RAG. "
            "Refuse iPhone work."
        ),
        "lane": "io",
        "queue": "android-build",
        "dispatch_agent": "extract_agent",
        "dispatch_action": "resume_extraction",
        "consults": ["iosagent", "performance_agent", "observe_agent"],
    },
    {
        "id": "list_folder_agent",
        "name": "List Folder Agent",
        "role": "action",
        "action": "List the evidence folder on the host drive",
        "lane": "io",
        "queue": "disk-build",
        "dispatch_agent": "extract_agent",
        "dispatch_action": "resume_extraction",
        "consults": ["drive_mount_agent", "download_agent", "segments_agent", "performance_agent"],
    },
    {
        "id": "segments_agent",
        "name": "Get Segments Agent",
        "role": "action",
        "action": "Register E01/EWF segments for the selected folder",
        "lane": "io",
        "queue": "disk-build",
        "dispatch_agent": "extract_agent",
        "dispatch_action": "resume_extraction",
        "consults": ["list_folder_agent", "virtual_disk_agent", "performance_agent"],
    },
    {
        "id": "virtual_disk_agent",
        "name": "Virtual Disk Agent",
        "role": "action",
        "action": "Build / mount the virtual disk from registered segments",
        "lane": "io",
        "queue": "disk-build",
        "dispatch_agent": "extract_agent",
        "dispatch_action": "resume_extraction",
        "consults": ["segments_agent", "extraction_agent", "performance_agent"],
    },
    {
        "id": "extraction_agent",
        "name": "Extraction Agent",
        "role": "action",
        "action": (
            "Own extract completeness: copy files into MinIO, then stand down when "
            "files_extracted >= files_total. Do not resume because status is processing "
            "or a leftover checkpoint remains"
        ),
        "lane": "io",
        "queue": "disk-build",
        "dispatch_agent": "extract_agent",
        "dispatch_action": "resume_extraction",
        "consults": ["virtual_disk_agent", "materialize_agent", "performance_agent"],
    },
    {
        "id": "materialize_agent",
        "name": "Materialize Agent",
        "role": "action",
        "action": "Register extracted files as job artifacts",
        "lane": "cpu",
        "queue": "disk-build",
        "dispatch_agent": "materialize_agent",
        "dispatch_action": "start_phase3",
        "consults": ["extraction_agent", "parse_agent", "performance_agent"],
    },
    {
        "id": "parse_agent",
        "name": "Parse Agent",
        "role": "action",
        "action": "Parse forensic files (EVTX, registry, SQLite, browsers)",
        "lane": "cpu",
        "queue": "disk-build",
        "dispatch_agent": "parse_agent",
        "dispatch_action": "parse_drain",
        "consults": ["ocr_agent", "artifacts_agent", "performance_agent"],
    },
    {
        "id": "ocr_agent",
        "name": "OCR Agent",
        "role": "action",
        "action": (
            "Own OCR completeness while running: drain pending and failed-without-text, "
            "stand down when the queue is empty (skipped/eligible gaps are finished), "
            "keep draining while the GPU is cool even if CPU is at throttle (~80°C)"
        ),
        "lane": "gpu",
        "queue": "ocr",
        "dispatch_agent": "ocr_agent",
        "dispatch_action": "ocr_drain",
        "consults": ["parse_agent", "chunk_agent", "performance_agent"],
    },
    {
        "id": "chunk_agent",
        "name": "RAG Chunk Agent",
        "role": "action",
        "action": "Split evidence text into searchable chunks",
        "lane": "cpu",
        "queue": "rag-index",
        "dispatch_agent": "rag_agent",
        "dispatch_action": "resume_rag",
        "consults": ["embed_agent", "ocr_agent", "performance_agent"],
    },
    {
        "id": "embed_agent",
        "name": "RAG Embed Agent",
        "role": "action",
        "action": "GPU embeddings (BGE-M3) for semantic search",
        "lane": "gpu",
        "queue": "rag-index",
        "dispatch_agent": "rag_agent",
        "dispatch_action": "resume_rag",
        "consults": ["chunk_agent", "ocr_agent", "performance_agent"],
    },
    {
        "id": "entity_agent",
        "name": "Entity Agent",
        "role": "action",
        "action": (
            "Own entity extraction: if graph is ready and enrich is not scanning, start rag_enrich. "
            "If the lock is held but scanned/updated_at is frozen, release and restart. "
            "Do not idle on a fake in-flight log or a 1% placeholder"
        ),
        "lane": "cpu",
        "queue": "disk-build",
        "dispatch_agent": "rag_enrich_agent",
        "dispatch_action": "rag_enrich",
        "consults": ["annotation_agent", "ontology_agent", "neo4j_agent", "performance_agent"],
    },
    {
        "id": "neo4j_agent",
        "name": "Neo4j Graph Agent",
        "role": "action",
        "action": "Sync evidence relationships into Neo4j",
        "lane": "cpu",
        "queue": "agent-orchestration",
        "dispatch_agent": "graph_agent",
        "dispatch_action": "graph_sync",
        "consults": ["entity_agent", "chunk_agent", "performance_agent"],
    },
    {
        "id": "annotation_agent",
        "name": "Annotation Agent",
        "role": "action",
        "action": (
            "Own evidence-span annotation: run alongside Entity/Ontology once the graph is ready"
        ),
        "lane": "cpu",
        "queue": "disk-build",
        "dispatch_agent": "rag_enrich_agent",
        "dispatch_action": "rag_enrich",
        "consults": ["entity_agent", "ontology_agent", "performance_agent"],
    },
    {
        "id": "ontology_agent",
        "name": "Ontology Agent",
        "role": "action",
        "action": (
            "Own ontology linking: run alongside Entity/Annotation once the graph is ready"
        ),
        "lane": "cpu",
        "queue": "disk-build",
        "dispatch_agent": "rag_enrich_agent",
        "dispatch_action": "rag_enrich",
        "consults": ["entity_agent", "annotation_agent", "performance_agent"],
    },
    {
        "id": "artifacts_agent",
        "name": "Artifact Inventory Agent",
        "role": "action",
        "action": "Count and catalog artifacts for the case inventory",
        "lane": "cpu",
        "queue": "disk-build",
        "dispatch_agent": "inventory_agent",
        "dispatch_action": "artifact_inventory",
        "consults": ["parse_agent", "performance_agent"],
    },
    {
        "id": "report_generator_agent",
        "name": "Report Evidence & Content Agent",
        "role": "action",
        "action": (
            "Own forensic report CONTENT only: map each selected objective to the supplied AXIOM/reference-report "
            "methodology and writing style learned from all supplied forensic exemplars, collect record-level artifacts, "
            "exclude noise, deduplicate/correlate evidence, and create Objective / Procedure / Observation, Annexure "
            "and Analysis Summary. The LLM is wording-only and may not invent evidence or counts. It does not own "
            "pagination or export formatting."
        ),
        "lane": "cpu",
        "queue": "report-gen",
        "dispatch_agent": "report_generator_agent",
        "dispatch_action": "start_report",
        "consults": ["artifacts_agent", "performance_agent", "observe_agent"],
    },
    {
        "id": "report_formation_agent",
        "name": "Report Formation Agent",
        "role": "action",
        "action": (
            "Own final report formation only: consume the exact saved UI report sections, pack them into A4 pages "
            "using all available remaining space (including annexure leftover body), preserve row/panel integrity, "
            "apply the reference-trained formal Introduction layout and very faint watermark, and create PDF and "
            "DOCX from the same canonical content snapshot. It is forbidden to rewrite, summarize, add, remove or "
            "reorder report content."
        ),
        "lane": "cpu",
        "queue": "report-gen",
        "dispatch_agent": "report_formation_agent",
        "dispatch_action": "form_report",
        "consults": ["report_generator_agent", "performance_agent"],
    },
)


def list_action_agents() -> list[dict[str, Any]]:
    return [dict(a) for a in ACTION_AGENTS]


def list_council_agents() -> list[dict[str, Any]]:
    return [dict(a) for a in COUNCIL_AGENTS]


def list_all_process_agents() -> list[dict[str, Any]]:
    return list_council_agents() + list_action_agents()


def _has_disk_source(row: dict | None) -> bool:
    if not row:
        return False
    src = row.get("disk_source")
    if isinstance(src, dict):
        return bool(src.get("evidence_folder") or src.get("path") or src.get("host_path"))
    return bool(src)


def _source_drive_letter(row: dict[str, Any] | None) -> str | None:
    src = (row or {}).get("disk_source") or {}
    if isinstance(src, dict):
        raw = str(src.get("evidence_folder") or src.get("path") or src.get("host_path") or "")
    else:
        raw = str(src or "")
    slash = raw.replace("\\", "/")
    host = re.match(r"(?i)/host/([a-z])(?:/|$)", slash)
    if host:
        return host.group(1).upper()
    win = re.match(r"^([a-zA-Z]):", raw.strip())
    if win:
        return win.group(1).upper()
    return None


def _platform_owner_vote(agent: dict[str, Any], snap: dict[str, Any]) -> dict[str, Any]:
    """iOS/Android Agent votes only on its own phone, and owns extract through RAG."""
    from app.services.mobile_platform_agents import ANDROIDAGENT_ID, IOSAGENT_ID, owner_agent_id

    aid = agent["id"]
    platform = snap.get("mobile_platform")
    owner = snap.get("owner_agent") or owner_agent_id(platform)
    if not snap.get("is_mobile"):
        return _vote(agent, "done", "Disk job — phone agent not in play")
    if owner and aid != owner:
        other = "iOS Agent" if owner == IOSAGENT_ID else "Android Agent"
        return _vote(agent, "done", f"{other} owns this phone — standing down")
    if aid == IOSAGENT_ID and platform == "android":
        return _vote(agent, "done", "Android phone — iOS Agent standing down")
    if aid == ANDROIDAGENT_ID and platform == "ios":
        return _vote(agent, "done", "iPhone — Android Agent standing down")
    if not owner and not platform:
        return _vote(agent, "wait", "Waiting to detect iPhone vs Android")

    health = snap.get("extract_health") or {}
    status = snap.get("status") or ""
    vote: dict[str, Any]
    if health.get("should_run") or health.get("live") or status in ("processing", "building_disk", "extracting"):
        if health.get("complete") or health.get("should_stand_down"):
            pass
        else:
            vote = _vote(agent, "run" if health.get("should_run") else "idle", "Extracting this phone into MinIO")
            vote["dispatch_agent"] = "extract_agent"
            vote["dispatch_action"] = "resume_extraction"
            return vote
    if int(snap.get("parse_pending") or 0) > 0:
        vote = _vote(agent, "run", "Parsing this phone's forensic files")
        vote["dispatch_agent"] = "parse_agent"
        vote["dispatch_action"] = "parse_drain"
        return vote
    if int(snap.get("rag_remaining") or 0) > 0:
        vote = _vote(agent, "run", "Indexing this phone into RAG")
        vote["dispatch_agent"] = "rag_agent"
        vote["dispatch_action"] = "resume_rag"
        return vote
    if status in ("created", "registered", "awaiting_segments") and not (
        snap.get("files_done") or (snap.get("row") or {}).get("extracted_disk_uri")
    ):
        vote = _vote(agent, "run", "Start extract and RAG for this phone")
        vote["dispatch_agent"] = "extract_agent"
        vote["dispatch_action"] = "resume_extraction"
        return vote
    if int((snap.get("row") or {}).get("files_extracted") or snap.get("files_done") or 0) <= 0:
        vote = _vote(agent, "run", "Start extract and RAG for this phone")
        vote["dispatch_agent"] = "extract_agent"
        vote["dispatch_action"] = "resume_extraction"
        return vote
    inv = snap.get("inventory") or {}
    if inv.get("total") and not inv.get("done"):
        vote = _vote(agent, "run", "Cataloging this phone's artifacts")
        vote["dispatch_agent"] = "inventory_agent"
        vote["dispatch_action"] = "artifact_inventory"
        return vote
    return _vote(agent, "done", "Phone extract and RAG complete")


def _agent_has_leftover(snap: dict[str, Any], aid: str) -> bool:
    """True only when a previously-done agent still has unfinished work."""
    if aid == "ocr_agent":
        from app.services.agent_duties import ocr_queue_health

        return bool(ocr_queue_health(snap)["should_run"])
    if aid == "parse_agent":
        return int(snap.get("parse_pending") or 0) > 0
    if aid == "chunk_agent":
        return int(snap.get("rag_remaining") or 0) > 0
    if aid == "embed_agent":
        return False
    if aid == "neo4j_agent":
        return (snap.get("graph_status") or "") not in ("ok", "skipped", "")
    if aid == "artifacts_agent":
        inv = snap.get("inventory") or {}
        return bool(inv.get("total")) and not inv.get("done")
    if aid in ("iosagent", "androidagent"):
        if not snap.get("is_mobile"):
            return False
        owner = snap.get("owner_agent")
        if owner and aid != owner:
            return False
        if int(snap.get("parse_pending") or 0) > 0:
            return True
        if int(snap.get("rag_remaining") or 0) > 0:
            return True
        inv = snap.get("inventory") or {}
        if inv.get("total") and not inv.get("done"):
            return True
        health = snap.get("extract_health") or {}
        return bool(health.get("should_run") or health.get("live"))
    if aid in ("entity_agent", "annotation_agent", "ontology_agent"):
        from app.services.agent_duties import enrich_agent_health

        return bool(enrich_agent_health(snap)["should_run"] or not snap.get("enrich_done"))
    if aid == "extraction_agent":
        from app.services.agent_duties import extract_agent_health

        return bool(extract_agent_health(snap)["should_run"])
    if aid == "drive_mount_agent":
        return not (
            snap.get("drives_ready")
            or snap.get("mounted_letters")
            or snap.get("client_upload")
        )
    if aid == "list_folder_agent":
        return not _list_folder_complete(snap)
    return False


def _orch_agent_done(snap: dict[str, Any], aid: str) -> bool:
    st = ((snap.get("agent_states") or {}).get(aid) or {}).get("state")
    return st == "done"


_POST_LIST_STATUSES = frozenset(
    {
        "processing",
        "building_disk",
        "extracting",
        "disk_ready",
        "extracted",
        "indexing",
        "indexed",
        "parsed",
        "artifacts_registered",
        "ready",
        "completed",
        "classified",
        "paused",
        "failed",
    }
)


def _list_folder_complete(snap: dict[str, Any]) -> bool:
    if snap.get("list_folder_done"):
        return True
    st = ((snap.get("agent_states") or {}).get("list_folder_agent") or {})
    if st.get("state") == "done":
        return True
    status = str(snap.get("status") or "")
    # Extract already running means listing finished earlier on this job.
    if status in _POST_LIST_STATUSES:
        return True
    return False


def _vote(agent: dict[str, Any], want: str, reason: str) -> dict[str, Any]:
    return {
        "id": agent["id"],
        "name": agent["name"],
        "lane": agent["lane"],
        "want": want,
        "reason": reason,
        "dispatch_agent": agent.get("dispatch_agent"),
        "dispatch_action": agent.get("dispatch_action"),
        "decision": "pending",
        "chair": "",
    }


def collect_action_votes(snap: dict[str, Any]) -> list[dict[str, Any]]:
    """Each action agent states run / wait / done / idle from the Observe snapshot."""
    from app.config import get_settings

    row = snap.get("row") or {}
    status = snap.get("status") or ""
    settings = get_settings()
    embed_on = bool(getattr(settings, "rag_embedding_enabled", False))
    inv = snap.get("inventory") or {}
    has_source = _has_disk_source(row)
    has_uri = bool(row.get("extracted_disk_uri"))
    files_total = int(snap.get("files_total") or 0)
    files_done = int(snap.get("files_done") or 0)
    from app.services.agent_duties import extract_agent_health as _extract_health

    extract_health = _extract_health(snap)
    snap["extract_health"] = extract_health
    # Counts win. Status=processing after a finished copy is not leftover extract.
    extracting_status = (
        status in ("processing", "building_disk", "extracting") and not extract_health["complete"]
    )
    early = status in ("created", "registered", "awaiting_segments")
    extracting = extract_health["should_run"] or extract_health["live"] or extracting_status
    indexed = status in (
        "indexing",
        "indexed",
        "parsed",
        "artifacts_registered",
        "extracted",
        "disk_ready",
        "processing",
        "building_disk",
        "paused",
    )
    baseline = (not embed_on) or int(snap.get("chunk_n") or 0) >= 500 or int(snap.get("artifact_n") or 0) > 0
    gs = snap.get("graph_status") or ""
    votes: list[dict[str, Any]] = []
    if snap.get("intake_started") is False:
        return [
            _vote(agent, "idle", "Waiting for examiner to select evidence")
            for agent in ACTION_AGENTS
        ]
    list_done = _list_folder_complete(snap) or bool(snap.get("is_mobile"))
    upload_pending = bool(snap.get("client_upload_pending"))
    from app.services.download_agent import download_block_reason

    ds_snap = (row or {}).get("disk_source") if isinstance((row or {}).get("disk_source"), dict) else {}
    download_wait = download_block_reason(ds_snap) if upload_pending else ""

    for agent in ACTION_AGENTS:
        aid = agent["id"]
        if aid in ("iosagent", "androidagent"):
            votes.append(_platform_owner_vote(agent, snap))
            continue
        if snap.get("is_mobile") and aid in (
            "drive_mount_agent",
            "download_agent",
            "virtual_disk_agent",
        ):
            votes.append(_vote(agent, "done", "Phone job — this agent is not in play"))
            continue
        if (
            _orch_agent_done(snap, aid)
            and not _agent_has_leftover(snap, aid)
            and not (aid == "download_agent" and upload_pending)
        ):
            votes.append(_vote(agent, "done", "Already complete — standing down"))
            continue
        if aid not in ("drive_mount_agent", "download_agent", "iosagent", "androidagent") and upload_pending:
            votes.append(_vote(agent, "wait", download_wait or "Waiting for Download Agent"))
            continue
        if aid not in ("drive_mount_agent", "download_agent", "list_folder_agent", "iosagent", "androidagent") and not list_done:
            votes.append(_vote(agent, "wait", "Waiting for List Folder Agent"))
            continue
        if aid == "drive_mount_agent":
            src = (row or {}).get("disk_source") or {}
            intake = str(src.get("intake") or "") if isinstance(src, dict) else ""
            if snap.get("client_upload") or intake == "browser_upload":
                votes.append(_vote(agent, "done", "Client upload — no office disk mount"))
                continue
            mounted = snap.get("mounted_letters") or []
            windows = snap.get("windows_letters") or []
            missing = snap.get("missing_letters") or []
            src_letter = _source_drive_letter(row)
            already_mounted = bool(mounted) or bool(snap.get("drives_ready"))
            # Once Docker has usable letters, stay done. Do not remount because an
            # unused Windows volume is missing. Only remount if the evidence letter
            # itself is absent, or if nothing is mounted yet.
            if already_mounted and not (src_letter and src_letter in missing):
                label = ", ".join(mounted or windows) if (mounted or windows) else "host drives"
                votes.append(_vote(agent, "done", f"Drives already mounted ({label}) — no remount"))
            elif missing and src_letter and src_letter in missing:
                votes.append(
                    _vote(
                        agent,
                        "run",
                        f"Evidence is on {src_letter}: but Docker is missing /host/{src_letter.lower()} — remount Windows drives",
                    )
                )
            elif has_source or files_done > 0 or has_uri:
                label = ", ".join(windows or mounted) if (windows or mounted) else "host drives"
                votes.append(_vote(agent, "done", f"Drives mounted ({label})"))
            else:
                votes.append(
                    _vote(
                        agent,
                        "idle",
                        "Waiting for images from this computer — no office disk mount",
                    )
                )
        elif aid == "download_agent":
            received = int(snap.get("download_received") or ds_snap.get("upload_received_files") or 0)
            expected = int(snap.get("download_expected") or ds_snap.get("upload_expected_files") or 0)
            slots = int(snap.get("download_parallelism") or 3)
            if upload_pending:
                votes.append(
                    _vote(
                        agent,
                        "run",
                        f"Receiving {received}/{expected or '?'} segment(s) with {slots} parallel slots — "
                        "other agents stay blocked until Download Agent signals complete",
                    )
                )
            elif snap.get("client_upload"):
                votes.append(
                    _vote(
                        agent,
                        "done",
                        f"All {received or expected or 'client'} segment(s) received — signaling other agents to start",
                    )
                )
            else:
                votes.append(
                    _vote(
                        agent,
                        "done",
                        "Download skipped — server-local evidence stays on the HDD/SSD/USB host path (zero copy)",
                    )
                )
        elif aid == "list_folder_agent":
            if list_done:
                votes.append(_vote(agent, "done", "Folder listing complete"))
            elif has_source or files_done > 0 or has_uri:
                votes.append(_vote(agent, "idle", "Listing every file in the evidence folder"))
            elif not snap.get("drives_ready"):
                votes.append(_vote(agent, "wait", "Waiting for Drive Mount Agent"))
            elif early:
                votes.append(_vote(agent, "idle", "Drives mounted — pick the .E01 folder"))
            else:
                votes.append(_vote(agent, "idle", "Folder step not in play"))
        elif aid == "segments_agent":
            if files_done > 0 or has_uri or status in ("indexing", "indexed", "disk_ready") or extracting_status:
                votes.append(_vote(agent, "done", "Segments already registered"))
            elif has_source and early:
                votes.append(_vote(agent, "run", "Folder known — register E01 segments"))
            else:
                votes.append(_vote(agent, "wait", "Waiting for List Folder Agent"))
        elif aid == "virtual_disk_agent":
            if has_uri or files_done > 0 or extracting_status:
                votes.append(_vote(agent, "done", "Virtual disk already built"))
            elif extracting and files_done <= 0:
                votes.append(_vote(agent, "run", "Segments ready — mount virtual disk"))
            else:
                votes.append(_vote(agent, "wait", "Waiting for Get Segments Agent"))
        elif aid == "extraction_agent":
            health = extract_health
            if health["should_stand_down"] or health["complete"]:
                votes.append(
                    _vote(
                        agent,
                        "done",
                        f"Extract complete ({health['files_done']:,}/{health['files_total']:,}) — do not resume",
                    )
                )
            elif health["live"]:
                phase = (
                    "enumerating filesystem"
                    if health["files_total"] <= 0 or health["files_done"] <= 0
                    else f"{health['files_done']:,}/{health['files_total']:,}"
                )
                votes.append(_vote(agent, "idle", f"Extract already running ({phase})"))
            elif health["should_run"]:
                votes.append(
                    _vote(
                        agent,
                        "run",
                        f"Extract unfinished ({health['files_done']:,}/{health['files_total']:,})",
                    )
                )
            else:
                votes.append(_vote(agent, "wait", "Waiting for virtual disk"))
        elif aid == "materialize_agent":
            if int(snap.get("artifact_n") or 0) > 0:
                votes.append(_vote(agent, "done", f"{snap['artifact_n']:,} artifacts registered"))
            elif status == "disk_ready" and (has_uri or files_done > 0):
                votes.append(_vote(agent, "run", "Extract finished — register artifacts"))
            else:
                votes.append(_vote(agent, "wait", "Waiting for Extraction Agent"))
        elif aid == "parse_agent":
            pending = int(snap.get("parse_pending") or 0)
            if extracting_status:
                votes.append(_vote(agent, "wait", "Waiting for Extraction Agent"))
            elif pending > 0 and indexed:
                votes.append(_vote(agent, "run", f"{pending:,} forensic files still to parse"))
            elif int(snap.get("artifact_n") or 0) > 0 and pending <= 0:
                votes.append(_vote(agent, "done", "Forensic parse drain is clear"))
            else:
                votes.append(_vote(agent, "wait", "Waiting for Materialize Agent"))
        elif aid == "ocr_agent":
            from app.services.agent_duties import ocr_queue_health

            health = ocr_queue_health(snap)
            pending = health["pending"]
            leftover = health["should_run"]
            ocr_done = health["done"]
            lanes = snap.get("lanes") or {}
            chassis = snap.get("chassis") if isinstance(snap.get("chassis"), dict) else {}
            thermal_note = ""
            if chassis.get("cpu_throttle_only") or chassis.get("cpu_warm_gpu_cool"):
                thermal_note = " — " + str(chassis.get("reason") or "CPU warm, GPU cool, keep draining")
            if extracting_status:
                votes.append(_vote(agent, "wait", "Waiting for Extraction Agent"))
            elif not settings.ocr_enabled:
                votes.append(_vote(agent, "idle", "OCR disabled"))
            elif leftover and indexed:
                n = pending if pending > 0 else max(int(health["unfinished"] or 0), 0)
                gpu_free = int(lanes.get("gpu_slots_free") if lanes.get("gpu_slots_free") is not None else 1)
                reason = (
                    f"{n:,} unfinished OCR documents — OCR Agent keeps draining"
                    f"{thermal_note}"
                )
                if lanes.get("ocr_lock"):
                    votes.append(_vote(agent, "run", reason + " (GPU GLM drain already running)"))
                elif gpu_free > 0:
                    votes.append(_vote(agent, "run", reason + " on CUDA GLM"))
                else:
                    votes.append(_vote(agent, "run", reason + " — waiting for CUDA slot"))
            elif health["should_stand_down"] or (ocr_done > 0 and health["queue_clear"]):
                if health["skipped_gap"] or health["fake_running"]:
                    votes.append(
                        _vote(
                            agent,
                            "done",
                            "OCR Agent standing down — queue empty; skipped/eligible gap is finished, not leftover",
                        )
                    )
                else:
                    votes.append(_vote(agent, "done", f"{ocr_done:,} documents OCR'd — OCR Agent standing down"))
            else:
                votes.append(_vote(agent, "wait", "Waiting for parse to mark OCR-eligible files"))
        elif aid == "chunk_agent":
            left = int(snap.get("rag_remaining") or 0)
            chunks = int(snap.get("chunk_n") or 0)
            if extracting_status:
                votes.append(_vote(agent, "wait", "Waiting for Extraction Agent"))
            elif left > 0 and indexed:
                votes.append(_vote(agent, "run", f"{left:,} artifacts still need chunks ({chunks:,} done)"))
            elif chunks > 0 and left <= 0:
                votes.append(_vote(agent, "done", f"{chunks:,} evidence chunks"))
            else:
                votes.append(_vote(agent, "wait", "Waiting for artifacts"))
        elif aid == "embed_agent":
            left = int(snap.get("rag_remaining") or 0)
            lanes = snap.get("lanes") or {}
            if not embed_on:
                votes.append(_vote(agent, "done", "Embeddings disabled — 100%"))
            elif extracting_status:
                votes.append(_vote(agent, "wait", "Waiting for Extraction Agent"))
            elif left > 0 and indexed:
                if not lanes.get("can_start_gpu", True):
                    votes.append(
                        _vote(agent, "wait", "Consulting Performance — GPU slot in use, embed waits")
                    )
                else:
                    share = "parallel with OCR" if lanes.get("can_share_gpu") else "GPU free"
                    votes.append(_vote(agent, "run", f"GPU embed {left:,} remaining ({share})"))
            elif left <= 0 and int(snap.get("chunk_n") or 0) > 0:
                votes.append(_vote(agent, "done", "Corpus embeddings complete"))
            else:
                votes.append(_vote(agent, "wait", "Waiting for RAG Chunk Agent"))
        elif aid == "neo4j_agent":
            if gs in ("ok", "skipped"):
                votes.append(_vote(agent, "done", f"Graph {gs}"))
            elif gs in ("queued", "syncing") and not snap.get("graph_stale"):
                votes.append(_vote(agent, "idle", f"Graph already {gs}"))
            elif baseline and status in ("indexing", "indexed"):
                reason = (
                    "Stale queued graph — restart Neo4j sync"
                    if snap.get("graph_stale")
                    else "Baseline ready — sync Neo4j now"
                )
                votes.append(_vote(agent, "run", reason))
            else:
                votes.append(_vote(agent, "wait", "Waiting for a RAG/chunk baseline"))
        elif aid == "entity_agent":
            from app.services.agent_duties import enrich_agent_health

            health = enrich_agent_health(snap)
            if health["should_stand_down"]:
                votes.append(_vote(agent, "done", "Entities extracted"))
            elif health["live"]:
                votes.append(
                    _vote(
                        agent,
                        "idle",
                        f"Entity Agent scanning {health.get('scanned') or 0:,}/"
                        f"{health.get('parse_total') or 0:,} parsed files",
                    )
                )
            elif health["should_run"]:
                votes.append(
                    _vote(
                        agent,
                        "run",
                        "Entity Agent: enrich frozen — restart scan"
                        if health.get("frozen")
                        else "Entity Agent: graph ready and enrich not scanning — start now",
                    )
                )
            else:
                votes.append(_vote(agent, "wait", "Waiting for Neo4j Graph Agent"))
        elif aid == "annotation_agent":
            from app.services.agent_duties import enrich_agent_health

            health = enrich_agent_health(snap)
            if health["should_stand_down"]:
                votes.append(_vote(agent, "done", "Annotations written"))
            elif health["live"]:
                votes.append(_vote(agent, "idle", "Annotation Agent already writing spans"))
            elif health["should_run"]:
                votes.append(
                    _vote(
                        agent,
                        "run",
                        "Annotation Agent: enrich frozen — restart scan"
                        if health.get("frozen")
                        else "Annotation Agent: graph ready — annotate alongside entity/ontology",
                    )
                )
            else:
                votes.append(_vote(agent, "wait", "Waiting for Entity Agent / graph"))
        elif aid == "ontology_agent":
            from app.services.agent_duties import enrich_agent_health

            health = enrich_agent_health(snap)
            if health["should_stand_down"]:
                votes.append(_vote(agent, "done", "Ontology links written"))
            elif health["live"]:
                votes.append(_vote(agent, "idle", "Ontology Agent already linking encyclopedia"))
            elif health["should_run"]:
                votes.append(
                    _vote(
                        agent,
                        "run",
                        "Ontology Agent: enrich frozen — restart scan"
                        if health.get("frozen")
                        else "Ontology Agent: graph ready — link ontology alongside entity/annotation",
                    )
                )
            else:
                votes.append(_vote(agent, "wait", "Waiting for Entity Agent / graph"))
        elif aid == "artifacts_agent":
            total = int(inv.get("total") or 0)
            if total > 0 and inv.get("done"):
                votes.append(_vote(agent, "done", f"Inventory {inv.get('completed') or 0:,}/{total:,}"))
            elif snap.get("inventory_inflight"):
                votes.append(_vote(agent, "idle", "Inventory already running"))
            elif total > 0 and not inv.get("done") and status in (
                "indexing",
                "indexed",
                "parsed",
                "artifacts_registered",
            ):
                votes.append(
                    _vote(
                        agent,
                        "run",
                        f"Inventory {inv.get('completed') or 0:,}/{total:,} — CPU lane beside parse",
                    )
                )
            else:
                votes.append(_vote(agent, "wait", "Waiting for artifacts to exist"))
        elif aid == "report_generator_agent":
            from app.services.agent_duties import report_generator_health

            health = report_generator_health(snap)
            if health["should_stand_down"]:
                votes.append(_vote(agent, "done", "Report Evidence & Content Agent standing down — recreate to rebuild forensic content"))
            else:
                votes.append(_vote(agent, "idle", "Report Evidence & Content Agent: artifacts -> objective/procedure/observation -> annexure/summary"))
        elif aid == "report_formation_agent":
            from app.services.report_formation_agent import formation_agent_health

            health = formation_agent_health(snap)
            votes.append(
                _vote(
                    agent,
                    "done" if health["should_stand_down"] else "idle",
                    "Report Formation Agent: exact UI content -> trained formal layout -> compact A4 -> identical PDF/DOCX",
                )
            )
        else:
            votes.append(_vote(agent, "idle", "No vote"))
    return votes


def performance_arbitrate(
    votes: list[dict[str, Any]],
    perf: dict[str, Any],
    *,
    gpu_abort: bool,
) -> list[dict[str, Any]]:
    """Performance chairs: go / hold from live GPU/CPU slots, not just a parallel flag."""
    from app.config import get_settings

    allow_parallel = bool(perf.get("allow_parallel", True))
    if not get_settings().pipeline_sequential_agents:
        allow_parallel = True
    safe = {str(x) for x in (perf.get("safe_parallel_agents") or [])}
    chassis = perf.get("chassis") if isinstance(perf.get("chassis"), dict) else {}
    too_hot = gpu_abort or bool((perf.get("gpu") or {}).get("too_hot")) or bool(chassis.get("too_hot"))
    sequential = not allow_parallel
    lanes = perf.get("lanes") if isinstance(perf.get("lanes"), dict) else {}
    gpu_free = int(lanes.get("gpu_slots_free") if lanes.get("gpu_slots_free") is not None else 1)
    can_cpu_heavy = bool(lanes.get("can_start_cpu_heavy", True))
    approved: list[dict[str, Any]] = []
    first_go_taken = False
    gpu_granted = 0

    for vote in votes:
        if vote.get("want") != "run":
            vote["decision"] = vote.get("want") or "idle"
            vote["chair"] = "Performance: no start needed"
            continue
        lane = vote.get("lane")
        disp = str(vote.get("dispatch_agent") or vote.get("id"))
        is_ocr = disp == "ocr_agent" or vote.get("id") == "ocr_agent"
        if is_ocr:
            if chassis and chassis.get("ocr_may_run") is False:
                vote["decision"] = "hold"
                vote["chair"] = "Performance: " + str(chassis.get("reason") or "chassis pause — hold new OCR GLM")
                continue
            if chassis.get("cpu_throttle_only") or chassis.get("cpu_warm_gpu_cool"):
                # OCR Agent duty: CPU ~80°C + cool GPU is not chassis abort.
                vote["decision"] = "go"
                vote["chair"] = "Performance: " + str(chassis.get("reason"))
                approved.append(vote)
                first_go_taken = True
                continue
            if too_hot and not chassis:
                vote["decision"] = "hold"
                vote["chair"] = "Performance: GPU abort margin — CPU lanes stay up"
                continue
        elif lane == "gpu" and too_hot:
            vote["decision"] = "hold"
            vote["chair"] = "Performance: GPU abort margin — CPU lanes stay up"
            continue
        if lane == "gpu" and gpu_granted >= max(gpu_free, 0):
            vote["decision"] = "hold"
            vote["chair"] = (
                f"Performance: GPU {lanes.get('gpu_slots_used') or 0}"
                f"/{lanes.get('gpu_slots_total') or 1} slots busy — {vote.get('id')} waits"
            )
            continue
        if disp == "extract_agent" and not can_cpu_heavy:
            vote["decision"] = "hold"
            vote["chair"] = "Performance: another extract holds the CPU-heavy slot"
            continue
        if disp in {"parse_agent", "materialize_agent", "inventory_agent"} and lane != "gpu":
            # CPU parse/materialize/inventory never wait for a GPU slot.
            pass
        if sequential and first_go_taken:
            vote["decision"] = "hold"
            vote["chair"] = "Performance: sequential mode — one action lane at a time"
            continue
        if safe and disp not in safe and vote.get("id") not in safe:
            # Throughput huddle still allows known process lanes.
            if disp not in {
                "extract_agent",
                "materialize_agent",
                "parse_agent",
                "ocr_agent",
                "rag_agent",
                "graph_agent",
                "rag_enrich_agent",
                "inventory_agent",
            }:
                vote["decision"] = "hold"
                vote["chair"] = f"Performance: {disp} not in live parallel set"
                continue
        vote["decision"] = "go"
        if lane == "gpu":
            gpu_granted += 1
            vote["chair"] = (
                f"Performance: go — GPU slot {gpu_granted}/"
                f"{lanes.get('gpu_slots_total') or gpu_free or 1}"
            )
        else:
            vote["chair"] = (
                "Performance: go — parallel CPU lane"
                if allow_parallel
                else "Performance: go — next sequential lane"
            )
        approved.append(vote)
        first_go_taken = True
    return approved


def votes_to_dispatch_recs(votes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Repair only starts unique worker tasks (siblings share extract/RAG/enrich)."""
    seen: set[tuple[str, str]] = set()
    recs: list[dict[str, Any]] = []
    for vote in votes:
        if vote.get("decision") != "go":
            continue
        agent = str(vote.get("dispatch_agent") or "")
        action = str(vote.get("dispatch_action") or "")
        if not agent or not action or (agent, action) in seen:
            continue
        seen.add((agent, action))
        recs.append(
            {
                "agent_id": agent,
                "action": action,
                "reason": f"{vote.get('name')}: {vote.get('reason')}",
            }
        )
    return recs
