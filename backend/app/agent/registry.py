"""Forensic AI agent registry — definitions for UI and orchestrator."""

from __future__ import annotations

from app.forensic_common.os_agents import OS_STAGE_AGENTS
from app.services.pipeline_supervisor import PIPELINE_STAGE_AGENTS

AGENT_DEFINITIONS: list[dict] = [
    {
        "id": "hostdrive_agent",
        "name": "HostDrive Agent",
        "description": (
            "Keeps the examiner host drive helper online (port 9876), detects attached "
            "HDD/USB/SSD drive letters, and refreshes Docker bind mounts for evidence browse."
        ),
        "stage": "host_evidence",
        "sort_order": 5,
        "kind": "host",
        "queue": None,
    },
    {
        "id": "investigator",
        "name": "Investigator",
        "description": "Multi-step evidence Q&A with retrieval tools and grounded answers.",
        "stage": "investigation",
        "sort_order": 10,
        "kind": "llm",
    },
    {
        "id": "intake_validator",
        "name": "Intake Validator",
        "description": "Checks case intake completeness before report generation.",
        "stage": "intake",
        "sort_order": 20,
        "kind": "llm",
    },
    {
        "id": "scope_advisor",
        "name": "Scope Advisor",
        "description": "Advises artifact scope based on job inventory and encyclopedia coverage.",
        "stage": "scope",
        "sort_order": 30,
        "kind": "llm",
    },
    {
        "id": "report_qa",
        "name": "Report QA",
        "description": "Reviews report sections for grounding and completeness.",
        "stage": "reporting",
        "sort_order": 40,
        "kind": "llm",
    },
]

# Pipeline stage agents — each owns one worker queue (extract, parse, RAG, graph, supervisor).
for idx, (agent_id, meta) in enumerate(PIPELINE_STAGE_AGENTS.items()):
    AGENT_DEFINITIONS.append({
        "id": agent_id,
        "name": meta["name"],
        "description": meta["description"],
        "stage": meta["stage"],
        "sort_order": 100 + idx,
        "kind": "pipeline",
        "queue": meta.get("queue"),
    })


# OS-family artifact agents — one per supported operating system. These were
# defined but never registered, so every image was scoped by the Windows-shaped
# default regardless of the OS actually detected.
for idx, (agent_id, meta) in enumerate(OS_STAGE_AGENTS.items()):
    AGENT_DEFINITIONS.append({
        "id": agent_id,
        "name": meta["name"],
        "description": meta["description"],
        "stage": meta["stage"],
        "sort_order": 200 + idx,
        "kind": "pipeline",
        "queue": meta.get("queue"),
        "domain": meta.get("domain"),
        "os_family": meta.get("os_family"),
        "axiom_platform": meta.get("axiom_platform"),
        "parsers": list(meta.get("parsers") or ()),
    })


def list_agent_definitions() -> list[dict]:
    return sorted(AGENT_DEFINITIONS, key=lambda a: int(a.get("sort_order") or 0))


def get_agent_definition(agent_id: str) -> dict | None:
    for a in AGENT_DEFINITIONS:
        if a["id"] == agent_id:
            return a
    return None
