import pytest
from app import create_app
from app.extensions import db as _db
from app.models import User

from config import TestConfig


@pytest.fixture(scope="session")
def app():
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()

        # Create a test admin
        user = User(email="test@example.com", role="admin")
        user.set_password("password123")
        _db.session.add(user)
        _db.session.commit()

        yield app

        _db.drop_all()


@pytest.fixture(scope="function")
def db(app):
    """Yields a fresh database session per test."""
    with app.app_context():
        yield _db


@pytest.fixture
def client(app):
    return app.test_client()
