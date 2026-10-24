"""
Secure email ingestion.

Responsibilities:
  * Validate an uploaded file is plausibly an RFC 5322 / MIME message.
  * Enforce size limits *before* reading the whole file into memory.
  * Generate a safe, non-guessable storage filename.
  * Write atomically to the upload folder (outside static/).
  * Compute SHA-256 so duplicate uploads can be deduplicated.

This module NEVER parses MIME content — that is Phase 5's job.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

# Reasonable header prefixes we accept as "looks like an email".
# If a file does not start with one of these (after optional BOM / whitespace),
# it is rejected. Real .eml files always start with a header line.
_MIME_HEADER_PREFIXES = (
    b"from:",
    b"from ",
    b"return-path:",
    b"return-path ",
    b"received:",
    b"dkim-signature:",
    b"delivered-to:",
    b"date:",
    b"to:",
    b"subject:",
    b"message-id:",
    b"mime-version:",
)

# Allow a few characters that can legitimately appear at the very start:
# - regular whitespace and newlines
# - UTF-8 BOM (\xef\xbb\xbf)
# We do NOT allow NUL bytes.
_LEADING_JUNK = b" \t\r\n\xef\xbb\xbf"
_ORIGINAL_FILENAME_RE = re.compile(r"[^A-Za-z0-9._\- ]+")


class IngestError(Exception):
    """Raised when a submitted file must be rejected."""


@dataclass(frozen=True)
class IngestResult:
    storage_path: Path
    storage_filename: str
    sha256: str
    size_bytes: int
    original_filename: str


def _sanitize_original_filename(name: str) -> str:
    name = (name or "message.eml").strip()
    name = os.path.basename(name)  # strip any path components
    name = _ORIGINAL_FILENAME_RE.sub("_", name)
    if not name.lower().endswith(".eml"):
        name = f"{name}.eml"
    return name[:200]


def _sniff_looks_like_email(head: bytes) -> bool:
    # Strip leading whitespace / BOM
    head = head.lstrip(b" \t\r\n\xef\xbb\xbf")
    lowered = head.lower()
    return any(lowered.startswith(p) for p in _MIME_HEADER_PREFIXES)


def ingest_uploaded_file(
    file_storage, upload_folder: Path, max_bytes: int
) -> IngestResult:
    """
    Validate and persist an uploaded .eml file.

    Raises IngestError on:
      - empty file
      - file larger than max_bytes
      - content that does not look like an RFC 5322 / MIME message
      - filesystem failure
    """
    original = _sanitize_original_filename(getattr(file_storage, "filename", "") or "")

    # Read the whole file once, bounded by max_bytes + 1 so we can detect oversize.
    data = file_storage.read(max_bytes + 1)
    if data is None:
        raise IngestError("Empty upload.")
    if len(data) == 0:
        raise IngestError("Empty upload.")
    if len(data) > max_bytes:
        raise IngestError(f"File exceeds the {max_bytes} byte limit.")

    # Basic content-type sanity (browsers send this; we do not trust it alone).
    if b"\x00" in data[:4096]:
        raise IngestError("Binary content rejected (NUL byte in header region).")

    if not _sniff_looks_like_email(data[:2048]):
        raise IngestError(
            "File does not appear to be an email message (missing RFC 5322 headers)."
        )

    sha = hashlib.sha256(data).hexdigest()
    storage_filename = f"{uuid.uuid4().hex}.eml"
    upload_folder.mkdir(parents=True, exist_ok=True)
    final_path = upload_folder / storage_filename

    # Atomic write: temp file in same dir, then os.replace (atomic on NTFS/ext4).
    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=str(upload_folder), prefix=".tmp_", suffix=".eml"
    )
    try:
        with os.fdopen(tmp_fd, "wb") as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, final_path)
    except Exception:
        # Best-effort cleanup of the temp file
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise IngestError("Failed to store uploaded file.")

    return IngestResult(
        storage_path=final_path,
        storage_filename=storage_filename,
        sha256=sha,
        size_bytes=len(data),
        original_filename=original,
    )
