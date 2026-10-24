"""
Risk Scoring Engine.

Aggregates detection findings into a final 0-100 score.
"""

from __future__ import annotations

from dataclasses import dataclass
from app.services.detection_engine import Finding


@dataclass
class RiskAssessment:
    score: int
    severity: str  # low, medium, high, critical
    verdict: str  # likely_benign, suspicious, likely_phishing, confirmed_malicious, inconclusive


def calculate_risk(findings: list[Finding]) -> RiskAssessment:
    if not findings:
        return RiskAssessment(score=0, severity="low", verdict="likely_benign")

    # 1. Aggregate raw score based on finding weights
    # raw_score = sum(f.weight for f in findings) # We use unique_score instead to prevent double-counting

    # 2. Prevent double-counting correlated indicators.
    seen_rules = set()
    unique_score = 0
    for f in findings:
        if f.rule_id not in seen_rules:
            unique_score += f.weight
            seen_rules.add(f.rule_id)

    # 3. Determine Severity Band (per blueprint §8.1)
    if unique_score >= 75:
        severity = "critical"
        verdict = "likely_phishing"
    elif unique_score >= 50:
        severity = "high"
        verdict = "likely_phishing"
    elif unique_score >= 25:
        severity = "medium"
        verdict = "suspicious"
    else:
        severity = "low"
        verdict = "inconclusive"

    # Cap at 100
    final_score = min(unique_score, 100)

    return RiskAssessment(
        score=final_score,
        severity=severity,
        verdict=verdict,
    )
