from dataclasses import dataclass, field
from typing import Callable, Any, Optional


# The context passed to every rule
@dataclass
class RuleContext:
    parsed_email: Any  # ParsedEmail from Phase 5
    iocs: Any  # ExtractedIOCs from Phase 6


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str  # info | low | medium | high | critical
    confidence: str  # low | medium | high
    evidence: dict  # Structured data proving the finding
    weight: int = 0  # Points toward the risk score (Phase 8)


# The signature every rule must implement
RuleFunc = Callable[[RuleContext], Optional[Finding]]
