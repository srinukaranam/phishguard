import io
import os
import pytest
from app.models import EmailCase, EmailArtifact, Finding
from app.services.email_parser import parse_email_file
from app.services.detection_engine import run_detection_engine
from app.services.ioc_extractor import extract_iocs
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_email_parser():
    """Test that parsing a benign email extracts the right headers."""
    parsed = parse_email_file(FIXTURES_DIR / "benign.eml")
    assert parsed.subject == "Meeting notes"
    assert "alice@example.com" in parsed.sender
    assert len(parsed.attachments) == 0


def test_ioc_extractor():
    """Test that we extract the raw IP from the phishing body."""
    parsed = parse_email_file(FIXTURES_DIR / "phishing.eml")
    iocs = extract_iocs(parsed.text_body, parsed.html_body, parsed.headers)
    assert "http://192.168.1.50/login" in iocs.urls
    assert "192.168.1.50" in iocs.ipv4s


def test_detection_engine():
    """Test that the rules fire on the phishing email."""
    parsed = parse_email_file(FIXTURES_DIR / "phishing.eml")
    iocs = extract_iocs(parsed.text_body, parsed.html_body, parsed.headers)
    findings = run_detection_engine(parsed, iocs)

    rule_ids = [f.rule_id for f in findings]
    assert "HDR-001" in rule_ids  # Reply-To mismatch
    assert "URL-001" in rule_ids  # IP in URL
    assert "ATT-001" in rule_ids  # Dangerous attachment


def test_upload_security_benign(client, db):
    """Test uploading a valid, safe file via the API."""
    # 1. Log in properly to get the session cookie
    client.post(
        "/auth/login", data={"email": "test@example.com", "password": "password123"}
    )

    with open(FIXTURES_DIR / "benign.eml", "rb") as f:
        data = {"file": (f, "benign.eml")}
        response = client.post(
            "/api/emails/analyze", data=data, content_type="multipart/form-data"
        )

    assert response.status_code == 201
    json_data = response.get_json()
    assert json_data["case_number"].startswith("CASE-")

    # Verify DB
    case = EmailCase.query.first()
    assert case.risk_score == 0
    assert case.verdict in ["likely_benign", "inconclusive"]


def test_upload_security_reject_binary(client, db):
    """Test that uploading a non-email file is rejected."""
    # 1. Log in properly
    client.post(
        "/auth/login", data={"email": "test@example.com", "password": "password123"}
    )

    # 2. Upload fake binary data (contains NUL byte)
    data = {"file": (io.BytesIO(b"MZ\x90\x00\x03"), "malware.exe")}
    response = client.post(
        "/api/emails/analyze", data=data, content_type="multipart/form-data"
    )

    assert response.status_code == 400
    # The ingestion service should catch the NUL byte or the missing MIME headers
    assert (
        b"Binary content rejected" in response.data
        or b"does not appear to be an email" in response.data
    )
