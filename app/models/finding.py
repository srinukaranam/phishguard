from datetime import datetime, timezone

from app.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(
        db.Integer,
        db.ForeignKey("email_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    rule_id = db.Column(db.String(64), nullable=False, index=True)  # e.g. "HDR-001"
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)

    severity = db.Column(
        db.String(16), nullable=False
    )  # info | low | medium | high | critical
    confidence = db.Column(
        db.String(16), nullable=False, default="medium"
    )  # low|medium|high

    # Evidence the analyst can inspect — a JSON structure containing the specific
    # values that triggered the rule (e.g. two addresses compared).
    evidence = db.Column(db.JSON, nullable=False)

    # Points contributed by this finding in the risk score (Phase 8 fills this in).
    weight = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    case = db.relationship("EmailCase", back_populates="findings")

    __table_args__ = (
        # Same rule shouldn't fire twice on the same case with identical evidence.
        # We use a partial-ish uniqueness via a hash on the app side (see Phase 7).
        db.Index("ix_findings_case_rule", "case_id", "rule_id"),
    )

    def __repr__(self) -> str:
        return f"<Finding {self.rule_id} sev={self.severity}>"
