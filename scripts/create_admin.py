"""
Create or update an admin user.

Usage (from project root, venv active, .env loaded):

    python -m scripts.create_admin --email admin@phishguard.local --password 'S0me-Str0ng!Pass'

If --password is omitted, the script will prompt (input is hidden).

Idempotent: if the user exists, only the password and role are updated
(and only when --update is passed). Otherwise it exits with an error.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from app import create_app
from app.extensions import db
from app.models import User


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Create or update a PhishGuard admin user.")
    p.add_argument("--email", required=True, help="Admin email address")
    p.add_argument("--password", help="Password (omit to be prompted)")
    p.add_argument(
        "--update",
        action="store_true",
        help="If the user exists, update password and force role=admin",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    email = args.email.strip().lower()
    password = args.password or getpass.getpass("Password: ")
    if len(password) < 12:
        print("ERROR: password must be at least 12 characters.", file=sys.stderr)
        return 2

    app = create_app()
    with app.app_context():
        existing = User.query.filter_by(email=email).first()

        if existing and not args.update:
            print(
                f"ERROR: user {email} already exists. Use --update to modify.",
                file=sys.stderr,
            )
            return 3

        if existing:
            existing.set_password(password)
            existing.role = "admin"
            existing.is_active_flag = True
            db.session.commit()
            print(f"Updated admin user: {email}")
            return 0

        user = User(email=email, role="admin", is_active_flag=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"Created admin user: {email} (id={user.id})")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
