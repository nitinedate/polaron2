"""Enterprise contextual risk scoring for vuln findings (BRD §9). Isolated from forensic RAG."""

from __future__ import annotations

from typing import Any


def score_finding(
    *,
    cvss: float | None,
    is_kev: bool = False,
    external_exposure: str | None = None,
    asset_criticality: str | None = None,
    days_open: int = 0,
    credentialed: bool = True,
) -> dict[str, Any]:
    technical = min(max(float(cvss or 0.0) / 10.0 * 25.0, 0.0), 25.0)
    threat = 12.0 if (cvss or 0) >= 7 else 6.0 if (cvss or 0) >= 4 else 2.0
    known = 15.0 if is_kev else 0.0
    exposure_map = {
        "internet-facing": 15.0,
        "partner": 10.0,
        "internal": 5.0,
        "isolated": 1.0,
    }
    exposure = exposure_map.get((external_exposure or "internal").lower(), 5.0)
    crit_map = {"tier0": 15.0, "tier1": 12.0, "tier2": 8.0, "tier3": 4.0, "0": 15.0, "1": 12.0, "2": 8.0, "3": 4.0}
    impact = crit_map.get((asset_criticality or "tier2").lower().replace(" ", ""), 8.0)
    age = min(days_open / 30.0 * 5.0, 5.0)
    confidence = 2.0 if credentialed else -2.0
    total = technical + threat + known + exposure + impact + age + confidence
    total = max(0.0, min(total, 100.0))
    if total >= 80:
        band = "critical"
    elif total >= 60:
        band = "high"
    elif total >= 40:
        band = "medium"
    elif total >= 20:
        band = "low"
    else:
        band = "info"
    return {
        "enterprise_risk_score": round(total, 2),
        "risk_band": band,
        "risk_factors_json": {
            "model_version": "brd-v2-contextual-1",
            "technical": round(technical, 2),
            "threat": round(threat, 2),
            "known_exploitation": known,
            "exposure": exposure,
            "impact": impact,
            "age": round(age, 2),
            "confidence": confidence,
        },
    }
