import logging
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    abort,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.models import AuditLog, EmailCase, EmailArtifact, AnalystNote
from app.models import Finding as DBFinding
from app.services.email_ingest import IngestError, ingest_uploaded_file
from app.services.email_parser import parse_email_file, EmailParseError
from app.services.ioc_extractor import extract_iocs
from app.services.detection_engine import run_detection_engine
from app.services.risk_scorer import calculate_risk
import threading
from app.services.threat_intel import enrich_case_artifacts
from flask import current_app

log = logging.getLogger(__name__)

analyze_bp = Blueprint("analyze", __name__)


def _next_case_number() -> str:
    """Generate a case number like CASE-2026-000001 (per-year counter)."""
    from datetime import datetime, timezone

    year = datetime.now(timezone.utc).year
    prefix = f"CASE-{year}-"
    existing = (
        db.session.query(EmailCase)
        .filter(EmailCase.case_number.like(f"{prefix}%"))
        .count()
    )
    return f"{prefix}{existing + 1:06d}"


@analyze_bp.get("/analyze")
@login_required
def analyze_page():
    return render_template(
        "analyze.html",
        max_upload_mb=current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
    )


@analyze_bp.post("/api/emails/analyze")
@login_required
def analyze_upload():
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "No file provided. Field name must be 'file'."}), 400

    upload_folder = Path(current_app.config["UPLOAD_FOLDER"])
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]

    try:
        result = ingest_uploaded_file(uploaded, upload_folder, max_bytes)
    except IngestError as exc:
        log.warning("Rejected upload from user=%s: %s", current_user.id, exc)
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action="email.upload_rejected",
                entity_type="email",
                extra={"reason": str(exc), "original_filename": uploaded.filename},
                ip_address=request.remote_addr,
            )
        )
        db.session.commit()
        return jsonify({"error": str(exc)}), 400

    existing = EmailCase.query.filter_by(evidence_sha256=result.sha256).first()
    if existing:
        log.info(
            "Duplicate upload detected (case=%s) for user=%s",
            existing.case_number,
            current_user.id,
        )
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action="email.duplicate_detected",
                entity_type="email_case",
                entity_id=existing.id,
                extra={"sha256": result.sha256},
                ip_address=request.remote_addr,
            )
        )
        db.session.commit()
        return (
            jsonify(
                {
                    "duplicate": True,
                    "case_id": existing.id,
                    "case_number": existing.case_number,
                    "redirect": url_for("analyze.case_preview", case_id=existing.id),
                }
            ),
            200,
        )

    parsed_subject = None
    parsed_sender = None
    parsed_received_at = None
    parse_error = None
    parsed = None
    try:
        parsed = parse_email_file(result.storage_path)
        parsed_subject = parsed.subject
        parsed_sender = parsed.sender
        if parsed.received_at:
            from datetime import datetime

            parsed_received_at = datetime.fromisoformat(parsed.received_at)
    except EmailParseError as exc:
        log.warning("Failed to parse uploaded email: %s", exc)
        parse_error = str(exc)

    # Calculate Risk Score
    findings = []
    if parsed:
        iocs = extract_iocs(parsed.text_body, parsed.html_body, parsed.headers)
        findings = run_detection_engine(parsed, iocs)

    assessment = calculate_risk(findings)

    # Create the case.
    case = EmailCase(
        case_number=_next_case_number(),
        subject=parsed_subject,
        sender=parsed_sender,
        received_at=parsed_received_at,
        risk_score=assessment.score,
        severity=assessment.severity,
        verdict=assessment.verdict,
        status="open",
        raw_evidence_path=str(result.storage_path),
        evidence_sha256=result.sha256,
        created_by=current_user.id,
    )
    db.session.add(case)
    db.session.flush()

    if parsed:

        def _add_artifact(artifact_type, val, sha=None):
            if not val:
                return
            db.session.add(
                EmailArtifact(
                    case_id=case.id,
                    artifact_type=artifact_type,
                    original_value=val,
                    normalized_value=val.strip().lower(),
                    sha256=sha,
                )
            )

        for url in iocs.urls:
            _add_artifact("url", url)
        for domain in iocs.domains:
            _add_artifact("domain", domain)
        for ip in iocs.ipv4s:
            _add_artifact("ip", ip)
        for email in iocs.emails:
            _add_artifact("email", email)

        for att in parsed.attachments:
            db.session.add(
                EmailArtifact(
                    case_id=case.id,
                    artifact_type="attachment",
                    original_value=att.filename,
                    normalized_value=att.filename.strip().lower(),
                    sha256=att.sha256,
                )
            )

        for f in findings:
            db.session.add(
                DBFinding(
                    case_id=case.id,
                    rule_id=f.rule_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    confidence=f.confidence,
                    evidence=f.evidence,
                    weight=f.weight,
                )
            )

    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action="email.upload_accepted",
            entity_type="email_case",
            entity_id=case.id,
            extra={
                "sha256": result.sha256,
                "size_bytes": result.size_bytes,
                "parse_error": parse_error,
            },
            ip_address=request.remote_addr,
        )
    )
    db.session.commit()

    # Run Threat Intel enrichment in the background so the browser doesn't hang
    app = current_app._get_current_object()
    threading.Thread(target=enrich_case_artifacts, args=(app, case.id)).start()
    log.info("Created case=%s user=%s", case.case_number, current_user.id)

    return (
        jsonify(
            {
                "case_id": case.id,
                "case_number": case.case_number,
                "status": case.status,
                "redirect": url_for("analyze.case_preview", case_id=case.id),
            }
        ),
        201,
    )


@analyze_bp.get("/cases/<int:case_id>/preview")
@login_required
def case_preview(case_id: int):
    case = db.session.get(EmailCase, case_id)
    if case is None:
        flash("Case not found.", "warning")
        return redirect(url_for("dashboard.index"))

    artifacts = case.artifacts.order_by(EmailArtifact.artifact_type).all()

    # Create a dict mapping artifact IDs to their latest VT lookup
    intel_map = {}
    for a in artifacts:
        latest = (
            a.lookups.filter_by(provider="virustotal")
            .order_by(db.desc("checked_at"))
            .first()
        )
        if latest:
            intel_map[a.id] = latest

    findings = case.findings.order_by(DBFinding.severity.desc()).all()
    notes = case.notes.order_by(AnalystNote.created_at.desc()).all()

    pipeline = {
        "ingested": True,
        "parsed": bool(case.subject or case.sender),
        "iocs": len(artifacts) > 0,
        "findings": len(findings) > 0,
        "scored": True,
        "enriched": len(intel_map) > 0,  # NEW Phase 11 flag
    }

    return render_template(
        "case_preview.html",
        case=case,
        artifacts=artifacts,
        findings=findings,
        notes=notes,
        pipeline=pipeline,
        intel_map=intel_map,
    )


@analyze_bp.post("/cases/<int:case_id>/notes")
@login_required
def add_note(case_id: int):
    case = db.session.get(EmailCase, case_id)
    if not case:
        abort(404)

    note_text = request.form.get("note", "").strip()
    if not note_text:
        flash("Note cannot be empty.", "warning")
        return redirect(url_for("analyze.case_preview", case_id=case.id))

    note = AnalystNote(case_id=case.id, user_id=current_user.id, note=note_text)
    db.session.add(note)
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action="case.note_added",
            entity_type="email_case",
            entity_id=case.id,
            ip_address=request.remote_addr,
        )
    )
    db.session.commit()
    flash("Note added successfully.", "success")
    return redirect(url_for("analyze.case_preview", case_id=case.id))


@analyze_bp.post("/cases/<int:case_id>/status")
@login_required
def update_status(case_id: int):
    case = db.session.get(EmailCase, case_id)
    if not case:
        abort(404)

    new_status = request.form.get("status")
    valid_statuses = ["open", "in_review", "closed"]

    if new_status in valid_statuses and case.status != new_status:
        old_status = case.status
        case.status = new_status
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action="case.status_changed",
                entity_type="email_case",
                entity_id=case.id,
                extra={"old": old_status, "new": new_status},
                ip_address=request.remote_addr,
            )
        )
        db.session.commit()
        flash(f"Case status updated to {new_status}.", "success")

    return redirect(url_for("analyze.case_preview", case_id=case.id))
