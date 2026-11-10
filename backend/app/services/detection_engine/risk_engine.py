import math
from typing import Any


def classify_risk(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH RISK"
    if score >= 25:
        return "SUSPICIOUS"
    return "LOW RISK"


def normalize_score(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def confidence_from_findings(findings: list[str], base: float = 55.0) -> float:
    return normalize_score(base + min(40, len(findings) * 2.5))


def build_scan_result(scanner_type: str, score: float, findings: list[str], recommendations: list[str], summary: str, metadata: dict | None = None) -> dict[str, Any]:
    score = normalize_score(score)
    result = {
        "scanner_type": scanner_type,
        "risk_score": round(score, 1),
        "confidence_score": round(confidence_from_findings(findings), 1),
        "threat_level": classify_risk(score),
        "status": "completed",
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations,
        "metadata": metadata or {},
    }
    return result
