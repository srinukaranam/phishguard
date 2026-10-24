import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://phishguard:change_me_dev_only@127.0.0.1:5432/phishguard_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Uploads
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_BYTES", 5 * 1024 * 1024))
    UPLOAD_FOLDER = BASE_DIR / "instance" / "uploads"  # never under static/
    ALLOWED_EXTENSIONS = {"eml"}

    # Sessions
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # set True behind HTTPS in production
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    WTF_CSRF_TIME_LIMIT = None

    # Threat intel (used later)
    # Threat intel (used later)
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    THREAT_INTEL_CACHE_TTL = 3600  # seconds (1 hour)


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql://phishguard:phishguard123@127.0.0.1:5432/phishguard_test",
    )
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret"
