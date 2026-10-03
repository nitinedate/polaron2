"""Report section order and rendering helpers."""

from __future__ import annotations

import re

SECTION_ORDER = [
    "cover_page",
    "table_of_contents",
    "introduction",
    "scope_of_work",
    "tools_used",
    "forensic_imaging",
    "os_information",
    "user_profile_information",
    "artifact_summary",
    "objectives_procedure_observation",
    "annexure",
    "final_analysis_summary",
    "appendix",
]

# Mobile forensic report layout — matches Aetheris mobile sample
# (e.g. "Mr. Sujit, Vivo V2403_Mobile Forensic Report.pdf").
# Disk / E01 reports keep SECTION_ORDER above unchanged.
MOBILE_SECTION_ORDER = [
    "cover_page",
    "table_of_contents",
    "introduction",
    "tools_used",
    "device_information",
    "extraction_summary",
    "objectives_procedure_observation",
    "annexure",
]

# Must match frontend ReportDocumentPreview.visibleSectionTitle — PDF/DOCX replica.
TITLES = {
    "cover_page": "CYBER FORENSIC ANALYSIS REPORT",
    "table_of_contents": "TABLE OF CONTENTS",
    "introduction": "INTRODUCTION",
    "scope_of_work": "SCOPE OF WORK",
    "tools_used": "TOOLS USED FOR ACQUISITION AND EXTRACTION",
    "forensic_imaging": "FORENSIC IMAGING",
    "evidence_details": "EVIDENCE DETAILS",
    "os_information": "A. OPERATING SYSTEM",
    "user_profile_information": "A. OPERATING SYSTEM (continued)",
    "device_information": "DEVICE INFORMATION",
    "extraction_summary": "EXTRACTION SUMMARY",
    "artifact_summary": "B. ARTIFACTS",
    "objectives_procedure_observation": "C. OBJECTIVE, PROCEDURE & OBSERVATION",
    "annexure": "D. ANNEXURE",
    "final_analysis_summary": "E. ANALYSIS SUMMARY",
    "appendix": "F. APPENDIX",
}

MOBILE_TITLES = {
    "cover_page": "MOBILE FORENSIC ANALYSIS REPORT",
    "table_of_contents": "TABLE OF CONTENTS",
    "introduction": "INTRODUCTION",
    "tools_used": "TOOLS USED FOR ACQUISITION AND ANALYSIS",
    "device_information": "DEVICE INFORMATION",
    "extraction_summary": "EXTRACTION SUMMARY",
    "objectives_procedure_observation": "OBJECTIVE, OBSERVATION with FINDINGS",
    "annexure": "ANNEXURE",
}


def section_order_for_report_type(report_type: str | None, intake: dict | None = None, job: dict | None = None) -> list[str]:
    from app.services.mobile_report_service import is_mobile_intake, is_mobile_report_type

    if is_mobile_intake(intake, job) or is_mobile_report_type(report_type):
        return list(MOBILE_SECTION_ORDER)
    return list(SECTION_ORDER)


def section_order_for_job(db, job_id: str) -> list[str]:
    """Resolve desktop vs mobile section order for a job."""
    from app.db.sql_helpers import fetchone

    intake = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id}) or {}
    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    return section_order_for_report_type(intake.get("report_type"), intake, job)


def section_title(key: str, *, mobile: bool = False) -> str:
    if mobile:
        return MOBILE_TITLES.get(key) or TITLES.get(key, key.replace("_", " ").title())
    return TITLES.get(key, key.replace("_", " ").title())


def _normalize_heading(text: str) -> str:
    text = re.sub(r"^#+\s*", "", text or "").strip()
    text = text.replace("&", " and ")
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def strip_redundant_section_heading(content: str, title: str) -> str:
    """Remove a leading markdown heading when the exporter already prints it.

    Saved section markdown frequently begins with the same section heading.  The old
    PDF/DOCX exporters printed both, which produced duplicated headings such as
    ``E. ANALYSIS SUMMARY`` twice on the same page.
    """
    lines = (content or "").replace("\r\n", "\n").split("\n")
    first_idx = next((idx for idx, line in enumerate(lines) if line.strip()), None)
    if first_idx is None:
        return content or ""
    first = lines[first_idx].strip()
    if not first.startswith("#"):
        return content or ""
    first_norm = _normalize_heading(first)
    title_norm = _normalize_heading(title)
    if not first_norm or not title_norm:
        return content or ""
    compatible = first_norm == title_norm
    if not compatible:
        a = first_norm.replace("objectives", "objective")
        b = title_norm.replace("objectives", "objective")
        compatible = a == b
    if compatible:
        del lines[first_idx]
        while lines and not lines[0].strip():
            lines.pop(0)
        return "\n".join(lines)
    return content or ""
