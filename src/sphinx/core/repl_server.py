"""REPL server — runs inside the Docker REPL container.

Listens for code blocks on a Unix socket, executes them in a persistent
namespace, and returns JSON results. The API container connects via
docker exec or socket mount.

Usage (inside REPL container):
    python -m sphinx.core.repl_server --socket /tmp/sphinx_repl.sock --db-url postgresql://...
"""

from __future__ import annotations

import io
import json
import os
import socketserver
import struct
import sys
import time
import traceback
from typing import Any

# Database URL injected via environment
DB_URL = os.environ.get("DATABASE_URL", "")

# Persistent namespace across steps
_namespace: dict[str, Any] = {}


def _init_namespace(
    case_id: str, task_id: int,
    mode: str = "investigator", source_case_ids: list[str] | None = None,
) -> None:
    """Reset and initialize the REPL namespace with tools."""
    import collections
    import datetime
    import hashlib
    import itertools
    import math
    import re as re_mod
    import statistics
    import uuid

    import psycopg

    # Determine readable case IDs
    if mode == "correlator" and source_case_ids:
        readable_ids = source_case_ids
    else:
        readable_ids = [case_id]

    # RLS session variable value — comma-separated case IDs
    _rls_case_ids = ",".join(readable_ids)

    def _get_conn(row_factory=psycopg.rows.dict_row):
        """Open a DB connection with RLS session variable set."""
        conn = psycopg.connect(DB_URL, row_factory=row_factory)
        conn.execute("SET app.readable_case_ids = %s", (_rls_case_ids,))
        return conn

    # Build tool functions
    def sql(query: str, params: tuple = ()) -> list[dict]:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall()

    def describe(record_type: str | None = None) -> str:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                if record_type is None:
                    cur.execute(
                        "SELECT record_type, count(*) AS cnt FROM records WHERE case_id = ANY(%s) GROUP BY record_type ORDER BY cnt DESC",
                        (readable_ids,),
                    )
                    rows = cur.fetchall()
                    return "\n".join(f"  {r['record_type']}: {r['cnt']}" for r in rows) if rows else "No records."
                else:
                    cur.execute(
                        "SELECT raw FROM records WHERE case_id = ANY(%s) AND record_type = %s LIMIT 1",
                        (readable_ids, record_type),
                    )
                    row = cur.fetchone()
                    if not row:
                        return f"No records of type '{record_type}'."
                    raw = row["raw"] if isinstance(row["raw"], dict) else {}
                    keys = sorted(raw.keys())
                    # Show SQL-ready access syntax so the model knows how to query
                    lines = [f"Table: records (filter: record_type = '{record_type}')"]
                    lines.append(f"JSONB keys in raw column: {', '.join(keys)}")
                    lines.append(f"Query: SELECT raw->>'key' FROM records WHERE case_id = CASE_ID AND record_type = '{record_type}'")
                    # Show nested structure for keys that are dicts
                    for k in keys:
                        v = raw.get(k)
                        if isinstance(v, dict):
                            subkeys = sorted(v.keys())
                            lines.append(f"  {k} (nested): {', '.join(subkeys)} — access via raw->'{k}'->>'subkey'")
                    return "\n".join(lines)

    def get_precomputed(name: str) -> Any:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                if len(readable_ids) == 1:
                    cur.execute(
                        "SELECT data FROM scratch_precomputed WHERE case_id = %s AND name = %s ORDER BY created_at DESC LIMIT 1",
                        (readable_ids[0], name),
                    )
                    row = cur.fetchone()
                    return row["data"] if row else None
                else:
                    cur.execute(
                        "SELECT case_id, data FROM scratch_precomputed WHERE case_id = ANY(%s) AND name = %s ORDER BY case_id, created_at DESC",
                        (readable_ids, name),
                    )
                    rows = cur.fetchall()
                    if not rows:
                        return None
                    return {r["case_id"]: r["data"] for r in rows}

    def get_docs(topic: str) -> str:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT content FROM rlm_docs WHERE topic = %s", (topic,))
                row = cur.fetchone()
                return row["content"] if row else f"No docs for '{topic}'."

    def query(record_type: str, fields: str = "*", where: str = "", params: tuple = (), limit: int = 100) -> list[dict]:
        """Query records by type with automatic case_id filtering.

        Example: query('suricata_alert', "raw->'alert'->>'signature' AS sig, id", limit=10)
        """
        sql_where = f"case_id = %s AND record_type = %s"
        sql_params = [readable_ids[0] if len(readable_ids) == 1 else readable_ids, record_type]
        if len(readable_ids) > 1:
            sql_where = f"case_id = ANY(%s) AND record_type = %s"
        if where:
            sql_where += f" AND ({where})"
            sql_params.extend(params)
        full_sql = f"SELECT {fields} FROM records WHERE {sql_where} LIMIT %s"
        sql_params.append(limit)
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(full_sql, sql_params)
                return cur.fetchall()

    def search(query: str, limit: int = 20) -> list[dict]:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, case_id, record_type, ts, raw::text AS raw_text FROM records WHERE case_id = ANY(%s) AND raw::text ILIKE %s LIMIT %s",
                    (readable_ids, f"%{query}%", limit),
                )
                return cur.fetchall()

    def stash(key: str, value, *, description: str = "") -> str:
        """Save intermediate results to the scratch database. Survives context limits.
        Retrieve later with recall(key). Overwrites if key exists.
        """
        import json as _json
        data_str = _json.dumps(value, default=str)
        meta = _json.dumps({"description": description, "size": len(data_str)})
        with _get_conn(row_factory=None) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM scratch_precomputed WHERE case_id = %s AND name = %s",
                    (case_id, f"_stash_{key}"),
                )
                cur.execute(
                    """INSERT INTO scratch_precomputed (case_id, task_id, name, plugin, data)
                       VALUES (%s, %s, %s, 'repl_stash', %s)""",
                    (case_id, task_id, f"_stash_{key}", data_str),
                )
            conn.commit()
        return f"Stashed '{key}' ({len(data_str)} bytes)"

    def recall(key: str):
        """Retrieve a previously stashed value by key. Returns None if not found."""
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT data FROM scratch_precomputed WHERE case_id = %s AND name = %s ORDER BY created_at DESC LIMIT 1",
                    (case_id, f"_stash_{key}"),
                )
                row = cur.fetchone()
                return row["data"] if row else None

    def stash_list() -> list:
        """List all stashed keys for the current task."""
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT name, created_at::text AS written_at,
                              pg_column_size(data) AS size_bytes
                       FROM scratch_precomputed
                       WHERE case_id = %s AND name LIKE '_stash_%%'
                       ORDER BY created_at""",
                    (case_id,),
                )
                return [
                    {"key": r["name"].replace("_stash_", "", 1),
                     "written_at": r["written_at"],
                     "size_bytes": r["size_bytes"]}
                    for r in cur.fetchall()
                ]

    _namespace.clear()
    _namespace.update({
        "__builtins__": __builtins__,
        "json": json,
        "re": re_mod,
        "collections": collections,
        "datetime": datetime,
        "math": math,
        "hashlib": hashlib,
        "itertools": itertools,
        "statistics": statistics,
        "uuid": uuid,
        "CASE_ID": case_id,
        "TASK_ID": task_id,
        "MODE": mode,
        "SOURCE_CASE_IDS": source_case_ids or [],
        "READABLE_CASE_IDS": readable_ids,
        "sql": sql,
        "query": query,
        "describe": describe,
        "get_precomputed": get_precomputed,
        "get_docs": get_docs,
        "search": search,
        "stash": stash,
        "recall": recall,
        "stash_list": stash_list,
        "trunc": lambda text, limit=64000: text[:limit] + "\n... [truncated]" if len(text) > limit else text,
        "result": None,
    })


def execute_code(code: str, timeout: int = 120) -> dict[str, Any]:
    """Execute a code block in the persistent namespace.

    Uses threading-based timeout instead of signal.alarm so it works
    from any thread (the REPL server uses ThreadingMixIn).
    """
    import ctypes
    import threading

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = cap_out = io.StringIO()
    sys.stderr = cap_err = io.StringIO()

    error = None
    t0 = time.monotonic()

    exec_done = threading.Event()

    def _run_code():
        nonlocal error
        try:
            exec(compile(code, "<repl>", "exec"), _namespace)
        except Exception:
            error = traceback.format_exc()
        finally:
            exec_done.set()

    worker = threading.Thread(target=_run_code, daemon=True)
    worker.start()

    if not exec_done.wait(timeout=timeout):
        # Timeout — try to interrupt the worker thread
        try:
            tid = worker.ident
            if tid is not None:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(
                    ctypes.c_ulong(tid),
                    ctypes.py_object(TimeoutError),
                )
        except Exception:
            pass
        error = f"Exceeded {timeout}s timeout"

    sys.stdout, sys.stderr = old_stdout, old_stderr

    elapsed = time.monotonic() - t0
    stdout = cap_out.getvalue()[:64_000]
    stderr = cap_err.getvalue()[:16_000]
    result_val = _namespace.get("result")

    return {
        "status": "error" if error else "ok",
        "stdout": stdout,
        "stderr": stderr,
        "error": error,
        "result": result_val,
        "elapsed_s": round(elapsed, 3),
    }


class ReplHandler(socketserver.StreamRequestHandler):
    """Handle a single REPL session over a Unix socket."""

    def handle(self):
        """Read length-prefixed JSON messages, execute, return results."""
        while True:
            try:
                # Read 4-byte length prefix
                header = self.rfile.read(4)
                if not header or len(header) < 4:
                    break
                msg_len = struct.unpack("!I", header)[0]
                raw = self.rfile.read(msg_len)
                if len(raw) < msg_len:
                    break

                msg = json.loads(raw.decode("utf-8"))
                cmd = msg.get("cmd", "exec")

                if cmd == "init":
                    _init_namespace(
                        msg["case_id"], msg["task_id"],
                        mode=msg.get("mode", "investigator"),
                        source_case_ids=msg.get("source_case_ids", []),
                    )
                    resp = {"status": "ok"}
                elif cmd == "exec":
                    resp = execute_code(msg["code"], msg.get("timeout", 120))
                    # Serialize result safely
                    if resp.get("result") is not None:
                        try:
                            json.dumps(resp["result"])
                        except (TypeError, ValueError):
                            resp["result"] = str(resp["result"])
                elif cmd == "pcap_convert":
                    # Run PCAP conversion pipeline (tshark + Suricata + Zeek)
                    try:
                        from sphinx.plugins.sphinx_plugin_pcap.convert import convert_pcap
                        resp = convert_pcap(
                            case_id=msg["case_id"],
                            pcap_path=msg["pcap_path"],
                            work_dir=msg.get("work_dir"),
                            job_id=msg.get("job_id"),
                            home_net=msg.get("home_net"),
                        )
                    except Exception as e:
                        resp = {"status": "error", "error": str(e)}
                elif cmd == "ping":
                    resp = {"status": "ok", "pong": True}
                else:
                    resp = {"status": "error", "error": f"Unknown command: {cmd}"}

                # Send response
                payload = json.dumps(resp, default=str).encode("utf-8")
                self.wfile.write(struct.pack("!I", len(payload)))
                self.wfile.write(payload)
                self.wfile.flush()

            except (ConnectionResetError, BrokenPipeError):
                break
            except Exception as e:
                try:
                    err = json.dumps({
                        "status": "error",
                        "error": str(e),
                        "stdout": "",
                        "stderr": "",
                        "result": None,
                        "elapsed_s": 0,
                    }).encode()
                    self.wfile.write(struct.pack("!I", len(err)))
                    self.wfile.write(err)
                    self.wfile.flush()
                except Exception:
                    break


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Sphinx REPL server")
    parser.add_argument("--socket", default="/tmp/sphinx_repl.sock")
    parser.add_argument("--db-url", default="")
    args = parser.parse_args()

    global DB_URL
    if args.db_url:
        DB_URL = args.db_url
    elif not DB_URL:
        DB_URL = "postgresql://sphinx_repl:repl_changeme@sphinx-db:5432/sphinx"

    # Clean up old socket
    import pathlib
    sock_path = pathlib.Path(args.socket)
    if sock_path.exists():
        sock_path.unlink()

    class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    server = ThreadedUnixServer(args.socket, ReplHandler)
    print(f"REPL server listening on {args.socket}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()