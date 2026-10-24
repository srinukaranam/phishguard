from app.services.detection_engine import RuleContext, Finding


def check_dangerous_attachments(ctx: RuleContext) -> Finding | None:
    dangerous_exts = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
    }
    matches = [
        att.filename
        for att in ctx.parsed_email.attachments
        if any(att.filename.lower().endswith(ext) for ext in dangerous_exts)
    ]
    if matches:
        return Finding(
            rule_id="ATT-001",
            title="Dangerous attachment type",
            description="Contains an attachment with a high-risk executable extension.",
            severity="critical",
            confidence="high",
            weight=25,
            evidence={"filenames": matches},
        )
    return None


def check_double_extension(ctx: RuleContext) -> Finding | None:
    matches = []
    for att in ctx.parsed_email.attachments:
        parts = att.filename.lower().split(".")
        if len(parts) >= 3:
            safe_exts = {"pdf", "docx", "xlsx", "jpg", "png", "txt"}
            danger_exts = {"exe", "scr", "bat", "vbs", "js"}
            if parts[-2] in safe_exts and parts[-1] in danger_exts:
                matches.append(att.filename)
    if matches:
        return Finding(
            rule_id="ATT-002",
            title="Double extension detected",
            description="Attachment uses a deceptive double extension.",
            severity="critical",
            confidence="high",
            weight=20,
            evidence={"filenames": matches},
        )
    return None


ATTACHMENT_RULES = [check_dangerous_attachments, check_double_extension]
