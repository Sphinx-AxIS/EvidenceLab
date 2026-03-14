"""Sphinx query learner — mines worklog steps for reusable query patterns."""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)

# Patterns to normalize: replace literal values with placeholders
_NORMALIZERS = [
    # IP addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<IP>"),
    # Quoted strings
    (re.compile(r"'[^']*'"), "'<STR>'"),
    # Numbers (but not in function names)
    (re.compile(r"(?<![a-zA-Z_])\d+(?![a-zA-Z_])"), "<NUM>"),
    # UUIDs
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "<UUID>"),
]


def normalize_query(code: str) -> str:
    """Normalize a code snippet by replacing literal values with placeholders."""
    normalized = code.strip()
    for pattern, replacement in _NORMALIZERS:
        normalized = pattern.sub(replacement, normalized)
    # Collapse whitespace
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def hash_pattern(normalized: str) -> str:
    """Generate a stable hash for a normalized query pattern."""
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def mine_worklog(min_frequency: int = 3) -> dict[str, Any]:
    """Scan worklog_steps for repeated query patterns.

    Extracts SQL queries and Python code patterns from completed tasks,
    normalizes them, and updates frequency counts in query_patterns table.

    Returns summary of patterns found.
    """
    with get_cursor() as cur:
        # Get all successful code steps
        cur.execute(
            """SELECT ws.code, ws.task_id
               FROM worklog_steps ws
               JOIN tasks t ON t.id = ws.task_id
               WHERE t.status = 'done'
                 AND ws.code IS NOT NULL
                 AND ws.code != ''
                 AND ws.error IS NULL
               ORDER BY ws.created_at"""
        )
        steps = cur.fetchall()

    if not steps:
        return {"patterns_found": 0, "new": 0, "updated": 0}

    # Extract and normalize patterns
    patterns: dict[str, dict] = {}  # hash -> {normalized, example, count}

    for step in steps:
        code = step["code"]
        # Extract SQL queries from sql() calls
        sql_matches = re.findall(r'sql\(["\'](.+?)["\']', code, re.DOTALL)
        for sql in sql_matches:
            normalized = normalize_query(sql)
            h = hash_pattern(normalized)
            if h not in patterns:
                patterns[h] = {
                    "normalized": normalized,
                    "example": sql[:500],
                    "count": 0,
                }
            patterns[h]["count"] += 1

        # Also track the full code block pattern
        normalized = normalize_query(code)
        h = hash_pattern(normalized)
        if h not in patterns:
            patterns[h] = {
                "normalized": normalized,
                "example": code[:500],
                "count": 0,
            }
        patterns[h]["count"] += 1

    # Upsert into query_patterns table
    new_count = 0
    updated_count = 0

    with get_cursor() as cur:
        for h, info in patterns.items():
            cur.execute(
                "SELECT id, frequency FROM query_patterns WHERE pattern_hash = %s",
                (h,),
            )
            existing = cur.fetchone()

            if existing:
                cur.execute(
                    """UPDATE query_patterns
                       SET frequency = frequency + %s, last_seen = now()
                       WHERE pattern_hash = %s""",
                    (info["count"], h),
                )
                updated_count += 1
            else:
                cur.execute(
                    """INSERT INTO query_patterns
                       (pattern_hash, normalized, example, frequency)
                       VALUES (%s, %s, %s, %s)""",
                    (h, info["normalized"], info["example"], info["count"]),
                )
                new_count += 1

        cur.connection.commit()

    # Report patterns above threshold
    with get_cursor() as cur:
        cur.execute(
            """SELECT pattern_hash, normalized, frequency, promoted
               FROM query_patterns
               WHERE frequency >= %s AND NOT promoted
               ORDER BY frequency DESC""",
            (min_frequency,),
        )
        candidates = cur.fetchall()

    log.info(
        "Query learning: %d patterns found, %d new, %d updated, %d promotion candidates",
        len(patterns), new_count, updated_count, len(candidates),
    )

    return {
        "patterns_found": len(patterns),
        "new": new_count,
        "updated": updated_count,
        "promotion_candidates": [
            {
                "hash": c["pattern_hash"],
                "pattern": c["normalized"][:100],
                "frequency": c["frequency"],
            }
            for c in candidates
        ],
    }


def promote_pattern(pattern_hash: str, precompute_fn: str) -> bool:
    """Promote a query pattern to a pre-computed function.

    Args:
        pattern_hash: The pattern to promote.
        precompute_fn: Dotted path to the precompute function.

    Returns True if promoted, False if pattern not found.
    """
    with get_cursor() as cur:
        cur.execute(
            """UPDATE query_patterns
               SET promoted = true, precompute_fn = %s
               WHERE pattern_hash = %s""",
            (precompute_fn, pattern_hash),
        )
        cur.connection.commit()
        return cur.rowcount > 0