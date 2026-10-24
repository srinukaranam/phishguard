import logging
from pathlib import Path

from flask import Flask

from config import Config
from app.extensions import csrf, db, login_manager, migrate, limiter


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=False)

    @app.after_request
    def add_security_headers(response):
        # Prevent the browser from guessing MIME types
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent the page from being embedded in an iframe (Clickjacking)
        response.headers["X-Frame-Options"] = "DENY"
        # Block scripts from loading (basic XSS protection)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:;"
        )
        return response

    app.config.from_object(config_class)

    # Ensure instance directories exist
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Logging (minimal; never log raw email content)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Blueprints (added in later phases — safe to register what exists)
    # Blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.analyze import analyze_bp
    from app.routes.cases import cases_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(analyze_bp)
    app.register_blueprint(cases_bp)

    # Health check (useful while building)
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    # Import models so migrations see them
    from app import models  # noqa: F401

    @app.get("/logout-redirect")
    def _dummy():
        return "", 204  # placeholder; not used

    @app.errorhandler(413)
    def _too_large(_e):
        from flask import jsonify, request

        if request.path.startswith("/api/"):
            return jsonify({"error": "Upload exceeds the configured size limit."}), 413
        return "Upload too large.", 413

    return app
