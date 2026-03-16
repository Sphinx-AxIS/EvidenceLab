"""Sphinx planner — prompt assembly and LLM conversation management."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from sphinx.core.config import Settings
from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)

# Maximum conversation history tokens before compaction
MAX_HISTORY_MESSAGES = 20


def build_system_prompt(
    case_id: str, plugin_prompts: dict[str, Any],
    mode: str = "investigator", source_case_ids: list[str] | None = None,
) -> str:
    """Assemble the system prompt from core + plugin prompts."""
    if mode == "correlator" and source_case_ids:
        readable_ids = source_case_ids
    else:
        readable_ids = [case_id]

    with get_cursor() as cur:
        # Case metadata
        cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
        case = cur.fetchone()

        # Record type summary (across all readable cases)
        cur.execute(
            """SELECT record_type, count(*) AS cnt
               FROM records WHERE case_id = ANY(%s)
               GROUP BY record_type ORDER BY cnt DESC""",
            (readable_ids,),
        )
        record_types = cur.fetchall()

        # Precomputed results available (across all readable cases)
        cur.execute(
            """SELECT DISTINCT name FROM scratch_precomputed
               WHERE case_id = ANY(%s)""",
            (readable_ids,),
        )
        precomputed = [r["name"] for r in cur.fetchall()]

        # Source case details (for correlator mode)
        source_cases = []
        if mode == "correlator" and source_case_ids:
            cur.execute(
                """SELECT c.id, c.name, count(r.id) AS record_count
                   FROM cases c
                   LEFT JOIN records r ON r.case_id = c.id
                   WHERE c.id = ANY(%s)
                   GROUP BY c.id ORDER BY c.name""",
                (source_case_ids,),
            )
            source_cases = cur.fetchall()

    # Build prompt sections
    sections = []

    sections.append("# Sphinx Investigation REPL\n")
    sections.append(
        "You are an incident response investigator. You write Python code "
        "that executes in a sandboxed REPL connected to a PostgreSQL database "
        "containing forensic evidence.\n"
    )

    sections.append("## Rules\n")
    sections.append(
        "- Write ONLY fenced Python code blocks. No prose outside code.\n"
        "- Do NOT simulate or predict output — the REPL executes your code.\n"
        "- Use `sql()` for queries. Fields are in `raw` JSONB: use `raw->>'field'` in SQL.\n"
        "- Set `result` at the end of every step.\n"
        "- When done: `result = {'status': 'done', 'summary': '...', 'citations': [record_ids]}`\n"
        "- Citations: ONLY include the most relevant record IDs (max 50). Do NOT cite all records.\n"
        "- MITRE ATT&CK: use `get_precomputed('mitre_detections')` — it returns "
        "[{technique_id, technique_name, tactic, evidence_count, sample_record_ids}].\n"
    )

    sections.append("## Available Tools\n")
    sections.append(
        "- `sql(query, params=())` — execute read-only SQL, returns list of dicts\n"
        "- `describe()` — list record types and counts\n"
        "- `describe('type')` — show fields for a record type\n"
        "- `get_precomputed('name')` — retrieve pre-computed analytics\n"
        "- `get_docs('topic')` — load on-demand documentation\n"
        "- `search('keyword', limit=20)` — full-text search across records\n"
        "- `trunc(text)` — truncate long output\n"
        "- `stash(key, value)` — save intermediate results to scratch DB\n"
        "- `recall(key)` — retrieve a previously stashed value\n"
        "- `stash_list()` — list all stashed keys\n"
        "\n### Scratch Storage (IMPORTANT)\n"
        "Use `stash(key, data)` to save large intermediate results (query outputs, "
        "filtered lists, aggregations) to the database. Then use `recall(key)` in "
        "later steps. This keeps context small and prevents data loss between steps. "
        "Do NOT hold large datasets in Python variables or result dicts — stash them.\n"
        "Example: `stash('suspicious_ips', suspicious_ips)`\n"
        "Later: `suspicious_ips = recall('suspicious_ips') or []`\n"
    )

    # Mode context
    if mode == "correlator" and source_cases:
        sections.append("## Mode: Cross-Case Correlator\n")
        sections.append(
            "You are analyzing evidence across multiple cases. "
            "All tool functions (describe, search, get_precomputed) query across "
            "all source cases. Findings and results write to the correlation case.\n\n"
        )
        sections.append(f"- Correlation Case (write target): {case['id']} — {case['name']}\n" if case else "")
        sections.append(f"- `READABLE_CASE_IDS` contains all source case IDs\n\n")
        sections.append("### Source Cases\n")
        for sc in source_cases:
            sections.append(f"- {sc['name']} ({sc['id'][:8]}…): {sc['record_count']} records\n")
        sections.append("\n")
    elif case:
        sections.append("## Case\n")
        sections.append(f"- ID: {case['id']}\n")
        sections.append(f"- Name: {case['name']}\n")
        if case.get("home_net"):
            sections.append(f"- HOME_NET: {', '.join(case['home_net'])}\n")
        if case.get("victim_ips"):
            sections.append(f"- Victim IPs: {', '.join(case['victim_ips'])}\n")

    # Evidence summary
    if record_types:
        sections.append("## Evidence in Database\n")
        for rt in record_types:
            sections.append(f"- {rt['record_type']}: {rt['cnt']} records\n")

    # Precomputed results
    if precomputed:
        sections.append("## Pre-computed Results Available\n")
        sections.append(
            "Call `get_precomputed('name')` to retrieve:\n"
        )
        for name in precomputed:
            sections.append(f"- {name}\n")

    # Plugin prompts
    for prompt_name, prompt_content in plugin_prompts.items():
        if isinstance(prompt_content, str):
            sections.append(f"\n## {prompt_name}\n")
            sections.append(prompt_content + "\n")

    return "".join(sections)


def build_first_step_message(task_text: str) -> str:
    """Build the user message for step 1 — forces discovery."""
    return (
        f"## Task\n\n{task_text}\n\n"
        f"max_steps=15\n\n"
        "## Step 1 — Discovery (MANDATORY)\n\n"
        "Your first code block MUST do ALL of the following:\n\n"
        "```\n"
        "# 1. List every record type\n"
        "print(describe())\n\n"
        "# 2. Inspect each record type you will query\n"
        "print(describe('suricata_alert'))  # example\n\n"
        "# 3. Check for pre-computed results\n"
        "print(get_precomputed('top_talkers'))  # example\n"
        "```\n\n"
        "Do NOT skip discovery. Do NOT guess field names.\n\n"
        "Reply with ONLY a fenced Python code block. "
        "Do NOT simulate or predict output — the REPL will execute "
        "your code and show you the real results.\n\n"
        "IMPORTANT: This is step 1 of a multi-step investigation. "
        "After discovery, you MUST continue with analysis steps. "
        "Do NOT set `result = {'status': 'done', ...}` on the discovery step. "
        "For discovery, set `result = {'status': 'discovery_complete'}` instead. "
        "Only set `status: 'done'` on your FINAL step when you have fully "
        "answered the task with evidence and citations."
    )


def build_step_message(step_num: int, stdout: str, error: str | None, result_val: Any = None, stash_keys: list | None = None) -> str:
    """Build a user message with the output from the previous step."""
    parts = [f"## Step {step_num} — REPL Output\n"]

    if stdout:
        parts.append(f"```\n{stdout[:8000]}\n```\n")

    # If no stdout but there's a result, show a truncated summary
    if not stdout and not error and result_val is not None:
        import json
        try:
            result_str = json.dumps(result_val, default=str)
            if len(result_str) > 2000:
                result_str = result_str[:2000] + "... [truncated]"
            parts.append(f"**Result (no print output — use `print()` to see data):**\n```\n{result_str}\n```\n")
        except Exception:
            parts.append("*Step produced a result but no printed output. Use `print()` to see data.*\n")
    if error:
        parts.append(f"**Error:**\n```\n{error}\n```\n")
        parts.append(
            "Fix the error. Use `describe('type')` to check field names. "
            "Do NOT give up — fix and continue.\n\n"
        )

    # Show stash contents so the model knows what intermediate data is available
    if stash_keys:
        parts.append(f"\n**Stash:** {', '.join(stash_keys)}\n")

    parts.append(
        "\nContinue the investigation. Write your next code block.\n\n"
        "When done: `result = {'status': 'done', 'summary': '...', "
        "'citations': [max 50 relevant record IDs as integers]}`"
    )

    return "".join(parts)


def compact_history(messages: list[dict]) -> list[dict]:
    """Trim conversation history to stay within context limits.

    Keeps: system prompt, first user message, last N messages.
    """
    if len(messages) <= MAX_HISTORY_MESSAGES:
        return messages

    # Keep system + first user + last messages
    keep_start = 2  # system + first user
    keep_end = MAX_HISTORY_MESSAGES - keep_start - 1
    compacted = messages[:keep_start]
    compacted.append({
        "role": "user",
        "content": (
            f"[Context: {len(messages) - keep_start - keep_end} intermediate "
            "steps were compacted. Continue from the most recent output.]"
        ),
    })
    compacted.extend(messages[-keep_end:])
    return compacted


def call_llm(
    settings: Settings,
    messages: list[dict],
    *,
    temperature: float = 0.0,
    max_tokens: int = 4096,
) -> str:
    """Call the LLM API (OpenAI-compatible). Returns content string."""
    url = f"{settings.lm_studio_url}/chat/completions"

    payload = {
        "model": settings.llm_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    with httpx.Client(timeout=300) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

    content = data["choices"][0]["message"]["content"]

    # Handle empty content (reasoning model exhaustion)
    if not content or not content.strip():
        log.warning("LLM returned empty content — possible reasoning exhaustion")
        return ""

    return content


def extract_code(response: str) -> str | None:
    """Extract the first fenced Python code block from LLM response."""
    import re
    # Match ```python ... ``` or ``` ... ```
    pattern = r"```(?:python)?\s*\n(.*?)```"
    match = re.search(pattern, response, re.DOTALL)
    if match:
        return match.group(1).strip()

    # If no fenced block, check if the entire response looks like code
    lines = response.strip().split("\n")
    if lines and not lines[0].startswith("#") and "=" in lines[0]:
        return response.strip()

    return None