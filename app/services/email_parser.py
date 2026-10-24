"""
Email parsing service.

Safely extracts headers, bodies, and attachment metadata from a raw `.eml` file.
Never executes, renders, or writes attachments to disk — it only hashes the payload.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import logging
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmail:
    # High-level metadata
    subject: str
    sender: str
    reply_to: str
    return_path: str
    message_id: str
    received_at: Optional[str]

    # Raw headers (case-insensitive dictionary emulation)
    headers: dict[str, str]

    # Bodies
    text_body: str
    html_body: str

    # Attachment metadata
    attachments: list[ParsedAttachment] = field(default_factory=list)

    # Parse errors / warnings
    errors: list[str] = field(default_factory=list)


class EmailParseError(Exception):
    """Raised when the email is so malformed it cannot be parsed at all."""

    pass


def _decode_header_value(value: str) -> str:
    """Safely decode RFC 2047 encoded headers (e.g., =?utf-8?B?...?=)."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def parse_email_file(file_path: Path) -> ParsedEmail:
    """
    Read and parse an .eml file.
    Raises EmailParseError if the file is completely unreadable.
    """
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except OSError as exc:
        raise EmailParseError(f"Could not read file: {exc}") from exc

    # `policy=email.policy.default` makes the parser more robust with modern
    # malformed emails, handling duplicate headers and unicode better.
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as exc:
        raise EmailParseError(f"Malformed MIME structure: {exc}") from exc

    # 1. Extract and decode headers
    headers_dict = {}
    for k, v in msg.items():
        headers_dict[k.lower()] = _decode_header_value(v)

    subject = headers_dict.get("subject", "")
    sender = headers_dict.get("from", "")
    reply_to = headers_dict.get("reply-to", "")
    return_path = headers_dict.get("return-path", "")
    message_id = headers_dict.get("message-id", "")

    received_at = None
    date_header = headers_dict.get("date")
    if date_header:
        try:
            # parsedate_to_datetime returns a timezone-aware datetime if possible
            received_at = parsedate_to_datetime(date_header).isoformat()
        except Exception:
            pass  # Date header was malformed; leave as None

    # 2. Extract bodies and attachments
    text_body = ""
    html_body = ""
    attachments = []
    errors = []

    # Walk the MIME tree
    for part in msg.walk():
        # Skip the root container and multipart boundaries
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", ""))

        # Extract the raw payload bytes exactly once
        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        # If it has a filename or is explicitly marked as an attachment,
        # we process it as an attachment.
        filename = part.get_filename()
        if filename:
            filename = _decode_header_value(filename)

        if filename or "attachment" in content_disposition.lower():
            sha = hashlib.sha256(payload).hexdigest()
            attachments.append(
                ParsedAttachment(
                    filename=filename or "unnamed",
                    content_type=content_type,
                    size_bytes=len(payload),
                    sha256=sha,
                )
            )
            continue

        # If it's a body, try to decode it to text
        if content_type == "text/plain" and not text_body:
            try:
                text_body = payload.decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception as exc:
                errors.append(f"Failed to decode text body: {exc}")

        elif content_type == "text/html" and not html_body:
            try:
                html_body = payload.decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception as exc:
                errors.append(f"Failed to decode HTML body: {exc}")

    return ParsedEmail(
        subject=subject,
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        message_id=message_id,
        received_at=received_at,
        headers=headers_dict,
        text_body=text_body,
        html_body=html_body,
        attachments=attachments,
        errors=errors,
    )
