from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, Length

from app.extensions import db, limiter
from app.models import AuditLog, User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=1, max=256)]
    )
    submit = SubmitField("Sign in")


def _log_login_attempt(user: User | None, action: str, success: bool) -> None:
    """Record authentication events. Never store the submitted password."""
    entry = AuditLog(
        user_id=user.id if user else None,
        action=action,
        entity_type="auth",
        entity_id=user.id if user else None,
        extra={"success": success},
        ip_address=request.remote_addr,
    )
    db.session.add(entry)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()

        # Constant-time-ish: always run check_password even when user is None.
        ok = bool(user and user.check_password(form.password.data))

        if not ok or (user and not user.is_active):
            _log_login_attempt(user, "auth.login_failed", success=False)
            db.session.commit()
            flash("Invalid email or password.", "error")
            return render_template("auth/login.html", form=form), 401

        login_user(user, remember=False)
        user.last_login_at = datetime.now(
            timezone.utc
        )  # see note below if field absent
        _log_login_attempt(user, "auth.login_success", success=True)
        db.session.commit()
        flash(f"Welcome, {user.email}.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("auth/login.html", form=form)


@auth_bp.post("/logout")
@login_required
def logout():
    _log_login_attempt(current_user, "auth.logout", success=True)
    db.session.commit()
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
