"""Sphinx REPL sandbox — restricted Python execution for LLM-generated code."""

from __future__ import annotations

import ast
import json
import logging
import re
import signal
import textwrap
import time
import traceback
from typing import Any

from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)

# Maximum output size per step (bytes)
MAX_OUTPUT = 64_000

# Imports the REPL is allowed to use
ALLOWED_IMPORTS = frozenset({
    "re", "json", "datetime", "collections", "math", "hashlib",
    "itertools", "statistics", "uuid", "textwrap", "csv", "io",
})

# Builtins that are banned
BANNED_CALLS = frozenset({
    "open", "eval", "exec", "compile", "__import__", "input", "help",
    "globals", "locals", "getattr", "setattr", "delattr", "breakpoint",
    "exit", "quit",
})


class SandboxViolation(Exception):
    """Raised when code violates sandbox policy."""


def validate_code(code: str) -> list[str]:
    """Parse and validate code against sandbox policy. Returns list of violations."""
    violations = []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"Syntax error: {e}"]

    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_IMPORTS:
                    violations.append(f"Import not allowed: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in ALLOWED_IMPORTS:
                violations.append(f"Import not allowed: {node.module}")

        # Check banned function calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in BANNED_CALLS:
                violations.append(f"Banned function call: {node.func.id}")

    return violations


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    """Truncate output to limit bytes."""
    if len(text) > limit:
        return text[:limit] + "\n... [truncated]"
    return text


class ReplRunner:
    """Executes LLM-generated Python code in a restricted environment."""

    def __init__(self, case_id: str, task_id: int, timeout: int = 120,
                 mode: str = "investigator", source_case_ids: list[str] | None = None):
        self.case_id = case_id
        self.task_id = task_id
        self.timeout = timeout
        self.mode = mode
        self.source_case_ids = source_case_ids or []
        self._globals: dict[str, Any] = {}
        self._setup_globals()

    def _readable_case_ids(self) -> list[str]:
        """Case IDs the REPL can read from."""
        if self.mode == "correlator" and self.source_case_ids:
            return self.source_case_ids
        return [self.case_id]

    def _setup_globals(self):
        """Initialize the REPL global namespace with tools and helpers."""
        import collections
        import datetime
        import hashlib
        import itertools
        import math
        import statistics
        import uuid

        self._globals = {
            "__builtins__": {
                k: v for k, v in __builtins__.items()
                if k not in BANNED_CALLS
            } if isinstance(__builtins__, dict) else {
                k: getattr(__builtins__, k)
                for k in dir(__builtins__)
                if k not in BANNED_CALLS and not k.startswith("_")
            },
            # Standard modules
            "json": json,
            "re": re,
            "collections": collections,
            "datetime": datetime,
            "math": math,
            "hashlib": hashlib,
            "itertools": itertools,
            "statistics": statistics,
            "uuid": uuid,
            # Case context
            "CASE_ID": self.case_id,
            "TASK_ID": self.task_id,
            "MODE": self.mode,
            "SOURCE_CASE_IDS": self.source_case_ids,
            "READABLE_CASE_IDS": self._readable_case_ids(),
            # Tool functions (bound to this case)
            "sql": self._tool_sql,
            "describe": self._tool_describe,
            "get_precomputed": self._tool_get_precomputed,
            "get_docs": self._tool_get_docs,
            "search": self._tool_search,
            "stash": self._tool_stash,
            "recall": self._tool_recall,
            "stash_list": self._tool_stash_list,
            "trunc": _truncate,
            # Result placeholder
            "result": None,
        }

    def _set_rls_context(self, cur) -> None:
        """Set the RLS session variable for case scoping."""
        case_ids_csv = ",".join(self._readable_case_ids())
        import psycopg.sql
        cur.execute(psycopg.sql.SQL("SET app.readable_case_ids = {}").format(
            psycopg.sql.Literal(case_ids_csv)
        ))

    def _tool_sql(self, query: str, params: tuple = ()) -> list[dict]:
        """Execute a read-only SQL query against the case data."""
        with get_cursor() as cur:
            self._set_rls_context(cur)
            cur.execute(query, params)
            return cur.fetchall()

    def _tool_describe(self, record_type: str | None = None) -> str:
        """Describe available record types or fields for a specific type."""
        readable = self._readable_case_ids()
        with get_cursor() as cur:
            if record_type is None:
                cur.execute(
                    """SELECT record_type, count(*) AS cnt
                       FROM records WHERE case_id = ANY(%s)
                       GROUP BY record_type ORDER BY cnt DESC""",
                    (readable,),
                )
                rows = cur.fetchall()
                if not rows:
                    return "No records in this case."
                lines = ["Record types:"]
                for r in rows:
                    lines.append(f"  {r['record_type']}: {r['cnt']} records")
                return "\n".join(lines)
            else:
                cur.execute(
                    """SELECT raw FROM records
                       WHERE case_id = ANY(%s) AND record_type = %s
                       LIMIT 1""",
                    (readable, record_type),
                )
                row = cur.fetchone()
                if not row:
                    return f"No records of type '{record_type}' found."
                raw = row["raw"] if isinstance(row["raw"], dict) else {}
                keys = sorted(raw.keys())
                lines = [f"Table: records (filter: record_type = '{record_type}')"]
                lines.append(f"JSONB keys in raw column: {', '.join(keys)}")
                lines.append(f"Query: SELECT raw->>'key' FROM records WHERE case_id = CASE_ID AND record_type = '{record_type}'")
                for k in keys:
                    v = raw.get(k)
                    if isinstance(v, dict):
                        subkeys = sorted(v.keys())
                        lines.append(f"  {k} (nested): {', '.join(subkeys)} — access via raw->'{k}'->>'subkey'")
                return "\n".join(lines)

    def _tool_get_precomputed(self, name: str) -> Any:
        """Retrieve a pre-computed result by name."""
        readable = self._readable_case_ids()
        with get_cursor() as cur:
            if len(readable) == 1:
                cur.execute(
                    """SELECT data FROM scratch_precomputed
                       WHERE case_id = %s AND name = %s
                       ORDER BY created_at DESC LIMIT 1""",
                    (readable[0], name),
                )
                row = cur.fetchone()
                return row["data"] if row else None
            else:
                cur.execute(
                    """SELECT case_id, data FROM scratch_precomputed
                       WHERE case_id = ANY(%s) AND name = %s
                       ORDER BY case_id, created_at DESC""",
                    (readable, name),
                )
                rows = cur.fetchall()
                if not rows:
                    return None
                return {r["case_id"]: r["data"] for r in rows}

    def _tool_get_docs(self, topic: str) -> str:
        """Retrieve on-demand documentation by topic."""
        # Check if rlm_docs table exists
        with get_cursor() as cur:
            cur.execute(
                """SELECT EXISTS (
                       SELECT FROM information_schema.tables
                       WHERE table_name = 'rlm_docs'
                   ) AS exists"""
            )
            if not cur.fetchone()["exists"]:
                return f"No documentation table available."
            cur.execute(
                "SELECT content FROM rlm_docs WHERE topic = %s",
                (topic,),
            )
            row = cur.fetchone()
            return row["content"] if row else f"No docs found for topic '{topic}'."

    def _tool_search(self, query: str, limit: int = 20) -> list[dict]:
        """Full-text search across records in readable cases."""
        readable = self._readable_case_ids()
        with get_cursor() as cur:
            cur.execute(
                """SELECT id, case_id, record_type, ts,
                          raw::text AS raw_text
                   FROM records
                   WHERE case_id = ANY(%s)
                     AND raw::text ILIKE %s
                   ORDER BY ts
                   LIMIT %s""",
                (readable, f"%{query}%", limit),
            )
            return cur.fetchall()

    def _tool_stash(self, key: str, value, *, description: str = "") -> str:
        """Save intermediate results to scratch DB. Retrieve with recall(key)."""
        data_str = json.dumps(value, default=str)
        with get_cursor() as cur:
            cur.execute(
                "DELETE FROM scratch_precomputed WHERE case_id = %s AND name = %s",
                (self.case_id, f"_stash_{key}"),
            )
            cur.execute(
                """INSERT INTO scratch_precomputed (case_id, task_id, name, plugin, data)
                   VALUES (%s, %s, %s, 'repl_stash', %s)""",
                (self.case_id, self.task_id, f"_stash_{key}", data_str),
            )
            cur.connection.commit()
        return f"Stashed '{key}' ({len(data_str)} bytes)"

    def _tool_recall(self, key: str):
        """Retrieve a previously stashed value. Returns None if not found."""
        with get_cursor() as cur:
            cur.execute(
                "SELECT data FROM scratch_precomputed WHERE case_id = %s AND name = %s ORDER BY created_at DESC LIMIT 1",
                (self.case_id, f"_stash_{key}"),
            )
            row = cur.fetchone()
            return row["data"] if row else None

    def _tool_stash_list(self) -> list:
        """List all stashed keys for the current task."""
        with get_cursor() as cur:
            cur.execute(
                """SELECT name, created_at::text AS written_at,
                          pg_column_size(data) AS size_bytes
                   FROM scratch_precomputed
                   WHERE case_id = %s AND name LIKE '_stash_%%'
                   ORDER BY created_at""",
                (self.case_id,),
            )
            return [
                {"key": r["name"].replace("_stash_", "", 1),
                 "written_at": r["written_at"],
                 "size_bytes": r["size_bytes"]}
                for r in cur.fetchall()
            ]

    def execute(self, code: str) -> dict[str, Any]:
        """Execute a code block and return the step result."""
        # Validate
        t0 = time.monotonic()
        violations = validate_code(code)
        validation_ms = (time.monotonic() - t0) * 1000

        if violations:
            return {
                "status": "error",
                "error": "Sandbox violation: " + "; ".join(violations),
                "stdout": "",
                "elapsed_s": 0,
                "validation_ms": validation_ms,
            }

        # Capture stdout
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()

        error = None
        t1 = time.monotonic()

        # Set timeout
        def _timeout_handler(signum, frame):
            raise TimeoutError(f"Step exceeded {self.timeout}s timeout")

        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(self.timeout)

        try:
            exec(compile(code, "<repl>", "exec"), self._globals)
        except TimeoutError as e:
            error = str(e)
        except Exception:
            error = traceback.format_exc()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
            sys.stdout = old_stdout

        elapsed = time.monotonic() - t1
        stdout = _truncate(captured.getvalue())

        # Extract result
        result_val = self._globals.get("result")

        return {
            "status": "error" if error else "ok",
            "stdout": stdout,
            "error": error,
            "result": result_val,
            "elapsed_s": round(elapsed, 3),
            "validation_ms": round(validation_ms, 2),
        }