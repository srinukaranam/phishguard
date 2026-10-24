"""
Rule-based detection engine.

Evaluates parsed emails and extracted IOCs against explainable heuristics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.services.email_parser import ParsedEmail
from app.services.ioc_extractor import ExtractedIOCs

log = logging.getLogger(__name__)


@dataclass
class RuleContext:
    parsed_email: ParsedEmail
    iocs: ExtractedIOCs


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    confidence: str  # low, medium, high
    evidence: dict
    weight: int  # Points contributed to the risk score (0-100)


def run_detection_engine(parsed: ParsedEmail, iocs: ExtractedIOCs) -> list[Finding]:
    """Runs all registered rules and returns a list of findings."""

    ctx = RuleContext(parsed_email=parsed, iocs=iocs)
    findings: list[Finding] = []

    # Import rules from the sub-folder
    from app.services.rules.header_rules import HEADER_RULES
    from app.services.rules.url_rules import URL_RULES
    from app.services.rules.attachment_rules import ATTACHMENT_RULES

    all_rules = HEADER_RULES + URL_RULES + ATTACHMENT_RULES

    for rule_func in all_rules:
        try:
            result = rule_func(ctx)
            if result is not None:
                findings.append(result)
        except Exception as exc:
            log.error("Rule %s failed: %s", rule_func.__name__, exc)

    return findings
