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

    def __init__(self, case_id: str, task_id: int, timeout: int = 120):
        self.case_id = case_id
        self.task_id = task_id
        self.timeout = timeout
        self._globals: dict[str, Any] = {}
        self._setup_globals()

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
            # Tool functions (bound to this case)
            "sql": self._tool_sql,
            "describe": self._tool_describe,
            "get_precomputed": self._tool_get_precomputed,
            "get_docs": self._tool_get_docs,
            "search": self._tool_search,
            "trunc": _truncate,
            # Result placeholder
            "result": None,
        }

    def _tool_sql(self, query: str, params: tuple = ()) -> list[dict]:
        """Execute a read-only SQL query against the case data."""
        with get_cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()

    def _tool_describe(self, record_type: str | None = None) -> str:
        """Describe available record types or fields for a specific type."""
        with get_cursor() as cur:
            if record_type is None:
                cur.execute(
                    """SELECT record_type, count(*) AS cnt
                       FROM records WHERE case_id = %s
                       GROUP BY record_type ORDER BY cnt DESC""",
                    (self.case_id,),
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
                       WHERE case_id = %s AND record_type = %s
                       LIMIT 1""",
                    (self.case_id, record_type),
                )
                row = cur.fetchone()
                if not row:
                    return f"No records of type '{record_type}' found."
                keys = sorted(row["raw"].keys()) if isinstance(row["raw"], dict) else []
                return f"Fields for '{record_type}': {', '.join(keys)}"

    def _tool_get_precomputed(self, name: str) -> Any:
        """Retrieve a pre-computed result by name."""
        with get_cursor() as cur:
            cur.execute(
                """SELECT data FROM scratch_precomputed
                   WHERE case_id = %s AND name = %s
                   ORDER BY created_at DESC LIMIT 1""",
                (self.case_id, name),
            )
            row = cur.fetchone()
            return row["data"] if row else None

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
        """Full-text search across records in this case."""
        with get_cursor() as cur:
            cur.execute(
                """SELECT id, record_type, ts,
                          raw::text AS raw_text
                   FROM records
                   WHERE case_id = %s
                     AND raw::text ILIKE %s
                   ORDER BY ts
                   LIMIT %s""",
                (self.case_id, f"%{query}%", limit),
            )
            return cur.fetchall()

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