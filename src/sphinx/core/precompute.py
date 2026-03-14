"""Sphinx pre-computation — runs plugin precompute functions before RLM loop."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from sphinx.core.db import get_cursor
from sphinx.core.plugin_loader import get_registry

log = logging.getLogger(__name__)


def run_precompute(case_id: str, task_id: int | None = None) -> dict[str, Any]:
    """Run all registered precompute functions for a case.

    Each function receives (case_id, cursor) and returns a dict with
    {name: str, data: Any}. Results are stored in scratch_precomputed.

    Returns summary of what was computed.
    """
    registry = get_registry()
    results = {}
    errors = {}

    for fn in registry.precompute_fns:
        fn_name = f"{fn.__module__}.{fn.__qualname__}"
        t0 = time.monotonic()

        try:
            with get_cursor() as cur:
                output = fn(case_id, cur)

            if not isinstance(output, dict) or "name" not in output:
                log.warning("Precompute %s returned invalid format", fn_name)
                errors[fn_name] = "Invalid return format (expected {name, data})"
                continue

            name = output["name"]
            data = output.get("data", {})

            # Store in scratch_precomputed
            with get_cursor() as cur:
                # Replace existing entry for this case+name
                cur.execute(
                    "DELETE FROM scratch_precomputed WHERE case_id = %s AND name = %s",
                    (case_id, name),
                )
                cur.execute(
                    """INSERT INTO scratch_precomputed (case_id, task_id, name, plugin, data)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (
                        case_id,
                        task_id,
                        name,
                        output.get("plugin", ""),
                        json.dumps(data),
                    ),
                )
                cur.connection.commit()

            elapsed = time.monotonic() - t0
            results[name] = {
                "rows": len(data) if isinstance(data, list) else 1,
                "elapsed_s": round(elapsed, 3),
            }
            log.info("Precompute %s -> %s (%.3fs)", fn_name, name, elapsed)

        except Exception as e:
            elapsed = time.monotonic() - t0
            errors[fn_name] = str(e)
            log.warning("Precompute %s failed (%.3fs): %s", fn_name, elapsed, e)

    return {
        "computed": results,
        "errors": errors,
        "total": len(results),
        "failed": len(errors),
    }


def clear_precomputed(case_id: str) -> int:
    """Remove all pre-computed results for a case. Returns count deleted."""
    with get_cursor() as cur:
        cur.execute(
            "DELETE FROM scratch_precomputed WHERE case_id = %s",
            (case_id,),
        )
        count = cur.rowcount
        cur.connection.commit()
    return count