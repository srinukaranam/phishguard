from datetime import datetime, timezone

from app.extensions import db


class EmailArtifact(db.Model):
    __tablename__ = "email_artifacts"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(
        db.Integer,
        db.ForeignKey("email_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    artifact_type = db.Column(db.String(32), nullable=False, index=True)
    # url | domain | ip | email | attachment | hash

    original_value = db.Column(db.Text, nullable=False)  # exact bytes as seen in email
    normalized_value = db.Column(
        db.Text, nullable=False
    )  # canonical form for dedup/lookup
    sha256 = db.Column(db.String(64), index=True)  # for attachments and hash artifacts

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    case = db.relationship("EmailCase", back_populates="artifacts")
    lookups = db.relationship(
        "IntelligenceLookup",
        back_populates="artifact",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    __table_args__ = (
        db.UniqueConstraint(
            "case_id",
            "artifact_type",
            "normalized_value",
            name="uq_artifact_case_type_value",
        ),
    )

    def __repr__(self) -> str:
        return f"<EmailArtifact {self.artifact_type}:{self.normalized_value[:60]}>"


class IntelligenceLookup(db.Model):
    __tablename__ = "intelligence_lookups"

    id = db.Column(db.Integer, primary_key=True)
    artifact_id = db.Column(
        db.Integer,
        db.ForeignKey("email_artifacts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    provider = db.Column(db.String(64), nullable=False)  # e.g. virustotal
    status = db.Column(
        db.String(32), nullable=False, default="ok"
    )  # ok | error | rate_limited | stale
    result = db.Column(db.String(32), nullable=False, default="unknown")
    # clean | suspicious | malicious | unknown | error

    positives = db.Column(db.Integer)  # engines that flagged it
    total_engines = db.Column(db.Integer)
    confidence = db.Column(db.String(16))  # low | medium | high — provider-declared
    raw_summary = db.Column(db.JSON)  # trimmed provider payload (never full raw)

    checked_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True))

    artifact = db.relationship("EmailArtifact", back_populates="lookups")

    def __repr__(self) -> str:
        return f"<IntelLookup {self.provider}:{self.result}>"
