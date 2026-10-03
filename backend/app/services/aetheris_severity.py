"""Aetheris finding severity — CVSS v3 bands plus policy floors.

Industry-standard CVSS v3 bands (not OpenVAS/Greenbone threat labels):

  critical  9.0–10.0
  high      7.0–8.9
  medium    4.0–6.9
  low       0.1–3.9
  info      0.0

Scanner threat labels (High / Medium / Low / Log) are ignored. Classification
is driven by the numeric CVSS score, with a small set of policy floors for
known weak-crypto findings that scanners often underscore.
"""

from __future__ import annotations

import os
import re
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_POLICY_FLOORS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(
            r"(?:ssl\s*(?:version\s*)?2.*ssl\s*(?:version\s*)?3|sslv2.*sslv3|"
            r"ssl version 2 and 3 protocol detection)",
            re.I,
        ),
        "critical",
        "legacy_ssl_v2_v3",
    ),
    (
        re.compile(r"(?:sweet32|medium[- ]strength.*cipher|64[- ]bit block cipher)", re.I),
        "high",
        "sweet32_3des",
    ),
)

_FLOOR_PROFILES = frozenset({"aetheris", "strict"})


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _profile() -> str:
    return (os.environ.get("VULN_SEVERITY_PROFILE") or "aetheris").strip().lower()


def apply_policy_floors(synopsis: str, severity: str) -> tuple[str, str | None]:
    if _profile() not in _FLOOR_PROFILES:
        return severity, None
    current = severity if severity in SEVERITY_RANK else "info"
    for pattern, floor, rule in _POLICY_FLOORS:
        if pattern.search(synopsis or ""):
            if SEVERITY_RANK[floor] > SEVERITY_RANK[current]:
                return floor, rule
            return current, rule
    return current, None


def classify_severity(
    *,
    cvss: float = 0.0,
    synopsis: str = "",
    raw_severity: Any = None,
) -> tuple[str, str | None]:
    """Return (severity, policy_rule). Scanner labels are not used."""
    del raw_severity  # OpenVAS/Greenbone threat is intentionally unused.
    try:
        score = float(cvss or 0)
    except (TypeError, ValueError):
        score = 0.0
    return apply_policy_floors(str(synopsis or ""), severity_from_cvss(score))


def aetheris_severity_sql(alias: str = "f") -> str:
    """SQL CASE that remaps stored rows onto Aetheris CVSS bands + policy floors."""
    prefix = f"{alias}." if alias else ""
    return f"""
CASE
  WHEN COALESCE({prefix}synopsis, '') ~* 'ssl[[:space:]]*(version[[:space:]]*)?2.*ssl[[:space:]]*(version[[:space:]]*)?3|sslv2.*sslv3|ssl version 2 and 3'
    THEN 'critical'
  WHEN COALESCE({prefix}synopsis, '') ~* 'sweet32|medium[- ]strength.*cipher|64[- ]bit block cipher'
    THEN 'high'
  WHEN COALESCE({prefix}cvss, 0) >= 9 THEN 'critical'
  WHEN COALESCE({prefix}cvss, 0) >= 7 THEN 'high'
  WHEN COALESCE({prefix}cvss, 0) >= 4 THEN 'medium'
  WHEN COALESCE({prefix}cvss, 0) > 0 THEN 'low'
  ELSE 'info'
END
""".strip()
