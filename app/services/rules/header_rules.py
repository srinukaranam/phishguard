from email.utils import parseaddr
from app.services.detection_engine import RuleContext, Finding


def check_reply_to_mismatch(ctx: RuleContext) -> Finding | None:
    from_addr = ctx.parsed_email.sender
    reply_to = ctx.parsed_email.reply_to
    if not from_addr or not reply_to:
        return None
    _, from_email = parseaddr(from_addr)
    _, reply_email = parseaddr(reply_to)
    if "@" not in from_email or "@" not in reply_email:
        return None
    from_domain = from_email.split("@")[1].lower()
    reply_domain = reply_email.split("@")[1].lower()
    if from_domain != reply_domain:
        return Finding(
            rule_id="HDR-001",
            title="Reply-To domain mismatch",
            description=f"Claims to be from '{from_domain}', but replies go to '{reply_domain}'.",
            severity="medium",
            confidence="high",
            weight=10,
            evidence={"from": from_addr, "reply_to": reply_to},
        )
    return None


def check_return_path_mismatch(ctx: RuleContext) -> Finding | None:
    from_addr = ctx.parsed_email.sender
    return_path = ctx.parsed_email.return_path
    if not from_addr or not return_path:
        return None
    _, from_email = parseaddr(from_addr)
    _, rp_email = parseaddr(return_path)
    if "@" not in from_email or "@" not in rp_email:
        return None
    from_domain = from_email.split("@")[1].lower()
    rp_domain = rp_email.split("@")[1].lower()
    if from_domain != rp_domain:
        return Finding(
            rule_id="HDR-002",
            title="Return-Path mismatch",
            description="Envelope sender does not match visible From domain.",
            severity="low",
            confidence="medium",
            weight=5,
            evidence={"from": from_addr, "return_path": return_path},
        )
    return None


def check_display_name_spoof(ctx: RuleContext) -> Finding | None:
    from_addr = ctx.parsed_email.sender
    if not from_addr:
        return None
    display_name, actual_email = parseaddr(from_addr)
    if not display_name or not actual_email:
        return None
    display_lower = display_name.lower()
    actual_domain = actual_email.split("@")[1].lower() if "@" in actual_email else ""
    if "@" in display_lower or "." in display_lower:
        if actual_domain and actual_domain not in display_lower:
            return Finding(
                rule_id="HDR-003",
                title="Potential display name spoofing",
                description="Display name contains a domain that does not match the actual sending domain.",
                severity="high",
                confidence="medium",
                weight=15,
                evidence={"display_name": display_name, "actual_email": actual_email},
            )
    return None


def check_missing_authentication(ctx: RuleContext) -> Finding | None:
    if not ctx.parsed_email.headers.get("authentication-results"):
        return Finding(
            rule_id="HDR-004",
            title="Missing Authentication-Results header",
            description="No Authentication-Results header found (SPF/DKIM/DMARC cannot be verified).",
            severity="info",
            confidence="high",
            weight=0,
            evidence={"header": "Authentication-Results"},
        )
    return None


HEADER_RULES = [
    check_reply_to_mismatch,
    check_return_path_mismatch,
    check_display_name_spoof,
    check_missing_authentication,
]
