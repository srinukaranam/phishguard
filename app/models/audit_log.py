from datetime import datetime, timezone

from app.extensions import db


class AnalystNote(db.Model):
    __tablename__ = "analyst_notes"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(
        db.Integer,
        db.ForeignKey("email_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    case = db.relationship("EmailCase", back_populates="notes")
    author = db.relationship("User", back_populates="notes")

    def __repr__(self) -> str:
        return f"<AnalystNote case={self.case_id} user={self.user_id}>"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), index=True
    )  # nullable for system events
    action = db.Column(
        db.String(64), nullable=False, index=True
    )  # case.create, case.status_change, login, ...
    entity_type = db.Column(db.String(64), nullable=False, index=True)
    entity_id = db.Column(db.Integer)
    extra = db.Column(db.JSON)  # small structured context, never raw email content
    ip_address = db.Column(db.String(45))  # IPv6 max length
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} {self.entity_type}:{self.entity_id}>"
