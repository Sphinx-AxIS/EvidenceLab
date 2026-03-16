"""Sphinx entity extractor — regex-based IOC extraction from record data."""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)

# ── Patterns ──────────────────────────────────────────

# IPv4
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# IPv6 (simplified — matches common forms)
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

# Domain (basic, avoids matching IPs)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|gov|edu|mil|co|info|biz|xyz|top|ru|cn|de|uk|fr|"
    r"jp|br|in|au|ca|onion|tk|ml|ga|cf|gq)\b",
    re.IGNORECASE,
)

# Email
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# URL
_RE_URL = re.compile(r"https?://[^\s\"'<>\]]+", re.IGNORECASE)

# MD5
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

# SHA1
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")

# SHA256
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Hostname (single label, uppercase common in Windows logs)
_RE_HOSTNAME = re.compile(r"\b[A-Z][A-Z0-9_-]{2,14}\b")

# Username patterns (DOMAIN\user) — require at least 2 chars on each side
# of the backslash and the right side must start with a letter to avoid
# matching escaped chars like \r \n \t in serialized data.
_RE_USERNAME = re.compile(r"\b[A-Za-z][A-Za-z0-9_-]{1,}\\[A-Za-z][A-Za-z0-9_.-]{1,}\b")

PATTERNS = {
    "ip": _RE_IPV4,
    "ipv6": _RE_IPV6,
    "domain": _RE_DOMAIN,
    "email": _RE_EMAIL,
    "url": _RE_URL,
    "hash_md5": _RE_MD5,
    "hash_sha1": _RE_SHA1,
    "hash_sha256": _RE_SHA256,
    "user": _RE_USERNAME,
}

# IPs to skip (broadcast, loopback, metadata)
_SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "169.254.169.254"}


def extract_from_text(text: str) -> list[dict[str, str]]:
    """Extract IOCs from a text string. Returns list of {type, value}."""
    results = []
    seen = set()

    for entity_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)

            # Skip common false positives
            if entity_type == "ip" and value in _SKIP_IPS:
                continue
            # Skip hex strings that are too short to be meaningful hashes
            if entity_type in ("hash_md5", "hash_sha1", "hash_sha256"):
                # Avoid matching version strings, timestamps, etc.
                if not all(c in "0123456789abcdefABCDEF" for c in value):
                    continue

            key = (entity_type, value.lower())
            if key not in seen:
                seen.add(key)
                results.append({"type": entity_type, "value": value})

    return results


def extract_from_record(raw: dict[str, Any]) -> list[dict[str, str]]:
    """Extract IOCs from a record's raw JSONB data."""
    import json
    text = json.dumps(raw) if isinstance(raw, dict) else str(raw)
    return extract_from_text(text)


def extract_and_store(case_id: str, record_id: int, raw: dict[str, Any], cur=None) -> int:
    """Extract entities from a record and store them in the entities table.

    If *cur* is provided, uses that cursor (same transaction as caller).
    Otherwise opens its own connection.  Returns the number of new entities inserted.
    """
    entities = extract_from_record(raw)
    if not entities:
        return 0

    def _insert(c):
        n = 0
        for entity in entities:
            c.execute(
                """INSERT INTO entities (case_id, record_id, entity_type, value)
                   SELECT %s, %s, %s, %s
                   WHERE NOT EXISTS (
                       SELECT 1 FROM entities
                       WHERE case_id = %s AND record_id = %s
                         AND entity_type = %s AND value = %s
                   )""",
                (
                    case_id, record_id, entity["type"], entity["value"],
                    case_id, record_id, entity["type"], entity["value"],
                ),
            )
            n += c.rowcount
        return n

    if cur is not None:
        return _insert(cur)

    with get_cursor() as c:
        inserted = _insert(c)
        c.connection.commit()
    return inserted


def bulk_extract_case(case_id: str, batch_size: int = 500) -> int:
    """Extract entities from all records in a case. Returns total inserted."""
    total = 0
    offset = 0

    while True:
        with get_cursor() as cur:
            cur.execute(
                """SELECT id, raw FROM records
                   WHERE case_id = %s
                   ORDER BY id
                   LIMIT %s OFFSET %s""",
                (case_id, batch_size, offset),
            )
            rows = cur.fetchall()

        if not rows:
            break

        for row in rows:
            total += extract_and_store(case_id, row["id"], row["raw"])

        offset += batch_size
        log.info("Entity extraction: processed %d records, %d entities so far",
                 offset, total)

    log.info("Entity extraction complete for case %s: %d entities", case_id, total)
    return total