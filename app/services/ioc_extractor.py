"""
IOC Extraction Service.

Extracts URLs, domains, IP addresses, and email addresses from parsed emails.
Uses regex for text extraction and HTMLParser for structural HTML extraction.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

import tldextract

log = logging.getLogger(__name__)

# Initialize tldextract once (it caches the public suffix list locally).
# fetch=False prevents network calls during extraction.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass
class ExtractedIOCs:
    urls: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    ipv4s: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)


class _HTMLLinkParser(HTMLParser):
    """Extracts href and src attributes from HTML bodies without rendering them."""

    def __init__(self):
        super().__init__()
        self.links: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        for attr in ("href", "src", "action"):
            if attr in attrs_dict:
                val = attrs_dict[attr].strip()
                if val:
                    self.links.add(val)


# Regex patterns
# Note: These are designed for extraction (triage), not absolute RFC validation.
_RE_URL = re.compile(r'https?://[^\s<>"\'\)]+', re.IGNORECASE)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b", re.IGNORECASE
)


def _extract_domain_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
        # Get registrable domain (e.g., sub.evil.com -> evil.com)
        ext = _tld_extract(parsed.hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return parsed.hostname
    except Exception:
        return None


def extract_iocs(
    text_body: str, html_body: str, headers: dict[str, str]
) -> ExtractedIOCs:
    iocs = ExtractedIOCs()

    # 1. Extract from plain text
    text_combined = f"{text_body}\n{html_body}"

    for match in _RE_URL.finditer(text_combined):
        url = match.group(0).rstrip(".,;)")
        iocs.urls.add(url)

    # 2. Extract from HTML structural tags (catches <a href="...">)
    if html_body:
        parser = _HTMLLinkParser()
        try:
            parser.feed(html_body)
            for link in parser.links:
                if link.lower().startswith(("http://", "https://")):
                    iocs.urls.add(link)
        except Exception as exc:
            log.warning("HTML parsing for links failed: %s", exc)

    # 3. IP addresses (search everywhere)
    for ip in _RE_IPV4.findall(text_combined):
        iocs.ipv4s.add(ip)

    # 4. Email addresses (search bodies and specific headers)
    header_emails = []
    for h in ("from", "reply-to", "return-path", "to", "cc"):
        if h in headers:
            header_emails.extend(_RE_EMAIL.findall(headers[h]))

    for email in header_emails + _RE_EMAIL.findall(text_combined):
        iocs.emails.add(email.lower())

    # 5. Domains (from URLs, emails, and raw text)
    for url in iocs.urls:
        domain = _extract_domain_from_url(url)
        if domain:
            iocs.domains.add(domain)

    for email in iocs.emails:
        parts = email.split("@")
        if len(parts) == 2:
            domain = _extract_domain_from_url(f"http://{parts[1]}")
            if domain:
                iocs.domains.add(domain)

    for match in _RE_DOMAIN.finditer(text_combined):
        domain = match.group(0).lower()
        # Filter out obvious false positives (like image extensions)
        if not domain.endswith((".png", ".jpg", ".gif", ".css", ".js")):
            iocs.domains.add(domain)

    # Normalization: clean up URL structures slightly
    iocs.urls = {u.strip() for u in iocs.urls if len(u) > 5}

    return iocs
