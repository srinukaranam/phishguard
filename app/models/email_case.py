from datetime import datetime, timezone

from app.extensions import db


class EmailCase(db.Model):
    __tablename__ = "email_cases"

    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(32), unique=True, nullable=False, index=True)

    subject = db.Column(db.String(998))  # RFC 5322 line limit
    sender = db.Column(db.String(320))
    received_at = db.Column(db.DateTime(timezone=True))

    risk_score = db.Column(db.Integer, nullable=False, default=0)  # 0..100
    severity = db.Column(
        db.String(16), nullable=False, default="low"
    )  # low|medium|high|critical
    verdict = db.Column(db.String(32), nullable=False, default="inconclusive")
    # likely_benign | suspicious | likely_phishing | confirmed_malicious | inconclusive
    status = db.Column(db.String(32), nullable=False, default="open")
    # open | in_review | closed

    # Where the raw .eml lives on disk (outside static/). Full message is NOT stored here.
    raw_evidence_path = db.Column(db.String(512))
    evidence_sha256 = db.Column(db.String(64), index=True)  # dedup helper

    created_by = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    creator = db.relationship("User", back_populates="cases")
    artifacts = db.relationship(
        "EmailArtifact",
        back_populates="case",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    findings = db.relationship(
        "Finding", back_populates="case", cascade="all, delete-orphan", lazy="dynamic"
    )
    notes = db.relationship(
        "AnalystNote",
        back_populates="case",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<EmailCase {self.case_number} score={self.risk_score} verdict={self.verdict}>"
