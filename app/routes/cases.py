from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import or_

from app.extensions import db
from app.models import EmailCase

cases_bp = Blueprint("cases", __name__, url_prefix="/cases")


@cases_bp.get("/")
@login_required
def index():
    # Get query parameters
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()

    query = EmailCase.query

    # Apply filters
    if q:
        search_term = f"%{q}%"
        query = query.filter(
            or_(
                EmailCase.case_number.ilike(search_term),
                EmailCase.subject.ilike(search_term),
                EmailCase.sender.ilike(search_term),
            )
        )

    if severity:
        query = query.filter(EmailCase.severity == severity)

    if status:
        query = query.filter(EmailCase.status == status)

    # Paginate results
    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(EmailCase.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template(
        "cases/index.html",
        pagination=pagination,
        q=q,
        selected_severity=severity,
        selected_status=status,
    )


@cases_bp.get("/<int:case_id>/report")
@login_required
def report(case_id: int):
    case = db.session.get(EmailCase, case_id)
    if not case:
        flash("Case not found.", "warning")
        return redirect(url_for("cases.index"))

    artifacts = case.artifacts.order_by("artifact_type").all()
    findings = case.findings.order_by("severity").all()
    notes = case.notes.order_by("created_at").all()

    # Get intelligence lookups
    intel_map = {}
    for a in artifacts:
        latest = (
            a.lookups.filter_by(provider="virustotal")
            .order_by(db.desc("checked_at"))
            .first()
        )
        if latest:
            intel_map[a.id] = latest

    return render_template(
        "cases/report.html",
        case=case,
        artifacts=artifacts,
        findings=findings,
        notes=notes,
        intel_map=intel_map,
        generated_at=__import__("datetime").datetime.now(),
    )
