from functools import wraps

from flask import abort
from flask_login import current_user


def admin_required(view):
    """Reject non-admin authenticated users with 403 (never 404 — 404 leaks existence)."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapper
