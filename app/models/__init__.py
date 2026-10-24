"""
Model registry.

Importing this module ensures every model is registered on `db.Model.metadata`
before Flask-Migrate/Alembic inspects it. Do not remove imports.
"""

from app.models.user import User
from app.models.email_case import EmailCase
from app.models.indicator import EmailArtifact, IntelligenceLookup
from app.models.finding import Finding
from app.models.audit_log import AnalystNote, AuditLog

__all__ = [
    "User",
    "EmailCase",
    "EmailArtifact",
    "IntelligenceLookup",
    "Finding",
    "AnalystNote",
    "AuditLog",
]
