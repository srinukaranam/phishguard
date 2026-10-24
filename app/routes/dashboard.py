from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user, login_required
from sqlalchemy import func

from app.extensions import db
from app.models import EmailCase, EmailArtifact, Finding

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/")
def index():
    # If not logged in, show the Cyberpunk Landing Page
    if not current_user.is_authenticated:
        return render_template("landing.html")

    # If logged in, show the SOC Dashboard
    total_cases = db.session.scalar(select_count(EmailCase))
    high_risk_cases = db.session.scalar(
        select_count(EmailCase, EmailCase.risk_score >= 75)
    )
    open_cases = db.session.scalar(select_count(EmailCase, EmailCase.status == "open"))
    suspicious_urls = db.session.scalar(
        select_count(EmailArtifact, EmailArtifact.artifact_type == "url")
    )

    recent_cases = EmailCase.query.order_by(EmailCase.created_at.desc()).limit(10).all()

    severity_rows = (
        db.session.query(EmailCase.severity, func.count(EmailCase.id))
        .group_by(EmailCase.severity)
        .all()
    )
    severity_distribution = {sev: int(count) for sev, count in severity_rows}

    recent_findings = (
        Finding.query.filter(Finding.severity.in_(["critical", "high"]))
        .order_by(Finding.created_at.desc())
        .limit(5)
        .all()
    )

    return render_template(
        "dashboard.html",
        user=current_user,
        stats={
            "total_cases": int(total_cases or 0),
            "high_risk_cases": int(high_risk_cases or 0),
            "open_cases": int(open_cases or 0),
            "suspicious_urls": int(suspicious_urls or 0),
        },
        severity_distribution=severity_distribution,
        recent_cases=recent_cases,
        recent_findings=recent_findings,
    )


def select_count(model, *conditions):
    from sqlalchemy import func as _func, select

    stmt = select(_func.count(model.id))
    if conditions:
        stmt = stmt.where(*conditions)
    return stmt
