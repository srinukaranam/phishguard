import logging
import time
import base64
from datetime import datetime, timezone, timedelta

import requests
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import EmailArtifact, IntelligenceLookup

log = logging.getLogger(__name__)

VT_API_URL = "https://www.virustotal.com/api/v3"
VT_ENDPOINTS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "attachment": "files",
}


def _query_virustotal(artifact_type: str, value: str, api_key: str) -> dict | None:
    """Perform the actual HTTP request to VirusTotal."""
    if not api_key:
        return None

    endpoint = VT_ENDPOINTS.get(artifact_type)
    if not endpoint:
        return None

    if artifact_type == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        target = f"{VT_API_URL}/{endpoint}/{url_id}"
    elif artifact_type == "attachment":
        target = f"{VT_API_URL}/{endpoint}/{value}"
    else:
        target = f"{VT_API_URL}/{endpoint}/{value}"

    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(target, headers=headers, timeout=15)

        if resp.status_code == 404:
            return {
                "status": "ok",
                "result": "unknown",
                "raw": {"message": "Not found in VT"},
            }

        if resp.status_code == 429:
            return {"status": "rate_limited", "result": "unknown", "raw": {}}

        if resp.status_code == 401:
            return {
                "status": "error",
                "result": "error",
                "raw": {"message": "Invalid API key"},
            }

        resp.raise_for_status()
        data = resp.json()

        stats = (
            data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0 or suspicious > 0:
            result = "malicious" if malicious > 2 else "suspicious"
        elif total > 0:
            result = "clean"
        else:
            result = "unknown"

        return {
            "status": "ok",
            "result": result,
            "positives": malicious + suspicious,
            "total": total,
            "raw": stats,
        }

    except requests.RequestException as exc:
        log.error("VirusTotal request failed for %s %s: %s", artifact_type, value, exc)
        return None  # Return None instead of a dict, so we skip saving to DB


def enrich_case_artifacts(app, case_id: int) -> None:
    """
    Look up artifacts for a case in VirusTotal.
    Saves results to IntelligenceLookup table. Respects caching.

    Takes the Flask app instance to set up the context, avoiding
    RuntimeError: Working outside of application context.
    """
    with app.app_context():
        api_key = app.config.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            print("❌ THREAT INTEL: No VirusTotal API key configured. Skipping.")
            return

        print(f"⏳ THREAT INTEL: Starting enrichment for case {case_id}...")

        artifacts = EmailArtifact.query.filter(
            EmailArtifact.case_id == case_id,
            EmailArtifact.artifact_type.in_(["url", "domain", "ip", "attachment"]),
        ).all()

        if not artifacts:
            print("❌ THREAT INTEL: No artifacts found to query.")
            return

        cache_ttl = timedelta(seconds=app.config.get("THREAT_INTEL_CACHE_TTL", 3600))
        now = datetime.now(timezone.utc)

        for artifact in artifacts:
            existing = (
                artifact.lookups.filter_by(provider="virustotal")
                .order_by(IntelligenceLookup.checked_at.desc())
                .first()
            )
            if existing and existing.expires_at and existing.expires_at > now:
                print(f"⏩ THREAT INTEL: Cache hit for {artifact.normalized_value}")
                continue

            print(
                f"🔍 THREAT INTEL: Querying VT for {artifact.artifact_type} -> {artifact.normalized_value}"
            )
            time.sleep(15)  # Rate limit

            result = _query_virustotal(
                artifact.artifact_type, artifact.normalized_value, api_key
            )

            if result is None:
                print("❌ THREAT INTEL: Query returned None.")
                continue

            print(f"✅ THREAT INTEL: Result -> {result['result']}")

            lookup = IntelligenceLookup(
                artifact_id=artifact.id,
                provider="virustotal",
                status=result["status"],
                result=result["result"],
                positives=result.get("positives"),
                total_engines=result.get("total"),
                confidence=(
                    "high" if result["result"] in ("malicious", "clean") else "low"
                ),
                raw_summary=result.get("raw"),
                checked_at=now,
                expires_at=now + cache_ttl,
            )
            db.session.add(lookup)

        try:
            db.session.commit()
            print(f"🎉 THREAT INTEL: Successfully enriched case {case_id}")
        except IntegrityError:
            db.session.rollback()
            log.warning("❌ THREAT INTEL: No VirusTotal API key configured. Skipping.")
