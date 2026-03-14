"""Sphinx RLM loop — step-bounded investigation engine."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from sphinx.core.config import Settings
from sphinx.core.db import get_cursor
from sphinx.core.planner import (
    build_first_step_message,
    build_step_message,
    build_system_prompt,
    call_llm,
    compact_history,
    extract_code,
)
from sphinx.core.plugin_loader import get_registry
from sphinx.core.sandbox import ReplRunner

log = logging.getLogger(__name__)


def _log_step(
    task_id: int,
    step_num: int,
    intent: str,
    code: str,
    stdout: str,
    error: str | None,
    result: Any,
    elapsed_s: float,
) -> None:
    """Write a worklog_step record for audit trail."""
    with get_cursor() as cur:
        cur.execute(
            """INSERT INTO worklog_steps
               (task_id, step_number, intent, code, stdout, stderr, result, elapsed_s)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                task_id,
                step_num,
                intent,
                code,
                stdout,
                error or "",
                json.dumps(result) if result else "{}",
                elapsed_s,
            ),
        )
        cur.connection.commit()


def _update_task_status(task_id: int, status: str) -> None:
    """Update task status and timestamps."""
    with get_cursor() as cur:
        if status == "running":
            cur.execute(
                "UPDATE tasks SET status = %s, started_at = now() WHERE id = %s",
                (status, task_id),
            )
        elif status in ("done", "failed"):
            cur.execute(
                "UPDATE tasks SET status = %s, completed_at = now() WHERE id = %s",
                (status, task_id),
            )
        else:
            cur.execute(
                "UPDATE tasks SET status = %s WHERE id = %s",
                (status, task_id),
            )
        cur.connection.commit()


def _store_finding(
    case_id: str,
    task_id: int,
    summary: str,
    citations: list[int],
) -> None:
    """Store a finding from a completed investigation."""
    with get_cursor() as cur:
        cur.execute(
            """INSERT INTO findings (case_id, task_id, title, body, evidence_ids)
               VALUES (%s, %s, %s, %s, %s)""",
            (case_id, task_id, summary[:200], summary, citations),
        )
        cur.connection.commit()


def run_task(settings: Settings, case_id: str, task_id: int) -> dict[str, Any]:
    """Execute an investigation task using the RLM loop.

    Returns a summary dict with status, steps taken, and findings.
    """
    max_steps = settings.rlm_max_steps
    timeout = settings.rlm_max_step_seconds

    # Get task details
    with get_cursor() as cur:
        cur.execute("SELECT * FROM tasks WHERE id = %s", (task_id,))
        task = cur.fetchone()
        if not task:
            return {"status": "error", "error": "Task not found"}

    task_text = f"{task['title']}\n\n{task['description']}" if task["description"] else task["title"]

    # Build system prompt with plugin prompts
    registry = get_registry()
    system_prompt = build_system_prompt(case_id, registry.prompts)

    # Initialize conversation
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": build_first_step_message(task_text)},
    ]

    # Initialize REPL
    repl = ReplRunner(case_id, task_id, timeout=timeout)

    _update_task_status(task_id, "running")
    log.info("Starting RLM loop for task %d (max %d steps)", task_id, max_steps)

    final_result = None

    for step in range(1, max_steps + 1):
        log.info("Task %d — Step %d/%d", task_id, step, max_steps)

        # Compact history if needed
        messages = compact_history(messages)

        # Call LLM
        try:
            response = call_llm(settings, messages, temperature=0.0, max_tokens=4096)
        except Exception as e:
            log.error("LLM call failed at step %d: %s", step, e)
            _log_step(task_id, step, "llm_call_failed", "", "", str(e), None, 0)
            break

        if not response:
            log.warning("LLM returned empty response at step %d", step)
            _log_step(task_id, step, "empty_response", "", "", "Empty LLM response", None, 0)
            break

        # Extract code
        code = extract_code(response)
        if not code:
            log.warning("No code block found in LLM response at step %d", step)
            _log_step(task_id, step, "no_code", "", response, "No code block found", None, 0)
            # Add response to conversation and try again
            messages.append({"role": "assistant", "content": response})
            messages.append({
                "role": "user",
                "content": "You must reply with a fenced Python code block. Try again.",
            })
            continue

        # Execute code
        step_result = repl.execute(code)

        # Log the step
        _log_step(
            task_id,
            step,
            f"step_{step}",
            code,
            step_result["stdout"],
            step_result.get("error"),
            step_result.get("result"),
            step_result["elapsed_s"],
        )

        # Add to conversation
        messages.append({"role": "assistant", "content": f"```python\n{code}\n```"})

        # Check if done
        result_val = step_result.get("result")
        if isinstance(result_val, dict) and result_val.get("status") == "done":
            final_result = result_val
            log.info("Task %d completed at step %d", task_id, step)
            break

        # Build next step message
        next_msg = build_step_message(
            step + 1,
            step_result["stdout"],
            step_result.get("error"),
        )
        messages.append({"role": "user", "content": next_msg})

    # Finalize
    if final_result:
        _update_task_status(task_id, "done")
        summary = final_result.get("summary", "Investigation complete.")
        citations = final_result.get("citations", [])
        _store_finding(case_id, task_id, summary, citations)
        return {
            "status": "done",
            "steps": step,
            "summary": summary,
            "citations": citations,
        }
    else:
        # Synthesize answer from accumulated findings
        log.info("Task %d exhausted %d steps — synthesizing answer", task_id, max_steps)
        synthesis = _synthesize_answer(settings, messages)
        _update_task_status(task_id, "done")
        _store_finding(case_id, task_id, synthesis, [])
        return {
            "status": "synthesized",
            "steps": max_steps,
            "summary": synthesis,
        }


def _synthesize_answer(settings: Settings, messages: list[dict]) -> str:
    """Final synthesis when loop exhausts max_steps without explicit 'done'."""
    messages = compact_history(messages)
    messages.append({
        "role": "user",
        "content": (
            "The investigation has reached its step limit. Based on all the "
            "evidence you've gathered so far, provide a final summary of your "
            "findings. Include specific evidence record IDs where possible. "
            "Reply in plain text, not code."
        ),
    })

    try:
        response = call_llm(settings, messages, temperature=0.2, max_tokens=4096)
        return response if response else "Investigation incomplete — no summary generated."
    except Exception as e:
        log.error("Synthesis call failed: %s", e)
        return f"Investigation incomplete — synthesis failed: {e}"