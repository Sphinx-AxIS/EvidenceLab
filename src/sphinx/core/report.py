"""Sphinx report generation — structured output with evidence citations."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from sphinx.core.config import Settings
from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)


def generate_report(settings: Settings, case_id: str) -> dict[str, Any]:
    """Generate a structured investigation report for a case.

    Collects findings, evidence, and worklog data, then optionally
    uses LLM for prose synthesis of the executive summary.
    """
    with get_cursor() as cur:
        # Case metadata
        cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
        case = cur.fetchone()
        if not case:
            return {"error": "Case not found"}

        # Findings
        cur.execute(
            """SELECT * FROM findings
               WHERE case_id = %s
               ORDER BY severity DESC, created_at""",
            (case_id,),
        )
        findings = cur.fetchall()

        # Tasks
        cur.execute(
            "SELECT * FROM tasks WHERE case_id = %s ORDER BY created_at",
            (case_id,),
        )
        tasks = cur.fetchall()

        # Entities (IOCs)
        cur.execute(
            """SELECT entity_type, value, count(*) AS cnt
               FROM entities WHERE case_id = %s
               GROUP BY entity_type, value
               ORDER BY cnt DESC
               LIMIT 50""",
            (case_id,),
        )
        iocs = cur.fetchall()

        # Record counts
        cur.execute(
            """SELECT record_type, count(*) AS cnt
               FROM records WHERE case_id = %s
               GROUP BY record_type ORDER BY cnt DESC""",
            (case_id,),
        )
        evidence_summary = cur.fetchall()

    # Build report structure (deterministic — no LLM needed)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": {
            "id": case["id"],
            "name": case["name"],
            "description": case["description"],
            "status": case["status"],
            "home_net": case["home_net"],
            "victim_ips": case["victim_ips"],
        },
        "evidence_summary": [
            {"type": r["record_type"], "count": r["cnt"]}
            for r in evidence_summary
        ],
        "tasks": [
            {
                "id": t["id"],
                "title": t["title"],
                "status": t["status"],
                "started_at": t["started_at"].isoformat() if t["started_at"] else None,
                "completed_at": t["completed_at"].isoformat() if t["completed_at"] else None,
            }
            for t in tasks
        ],
        "findings": [
            {
                "id": f["id"],
                "title": f["title"],
                "body": f["body"],
                "severity": f["severity"],
                "evidence_ids": f["evidence_ids"],
                "mitre_ids": f["mitre_ids"],
            }
            for f in findings
        ],
        "iocs": [
            {"type": i["entity_type"], "value": i["value"], "count": i["cnt"]}
            for i in iocs
        ],
    }

    # Optionally synthesize executive summary with LLM
    if findings:
        try:
            report["executive_summary"] = _synthesize_executive_summary(
                settings, case, findings, iocs
            )
        except Exception as e:
            log.warning("Executive summary synthesis failed: %s", e)
            report["executive_summary"] = _build_deterministic_summary(
                case, findings, iocs
            )
    else:
        report["executive_summary"] = "No findings recorded for this case."

    return report


def _synthesize_executive_summary(
    settings: Settings,
    case: dict,
    findings: list[dict],
    iocs: list[dict],
) -> str:
    """Use LLM to generate executive summary prose from findings."""
    findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']}: {f['body'][:200]}"
        for f in findings
    )
    ioc_text = "\n".join(
        f"- {i['entity_type']}: {i['value']} ({i['cnt']}x)"
        for i in iocs[:20]
    )

    prompt = (
        f"Write a concise executive summary (3-5 paragraphs) for this "
        f"incident response investigation.\n\n"
        f"Case: {case['name']}\n"
        f"Description: {case['description']}\n\n"
        f"Findings:\n{findings_text}\n\n"
        f"Key IOCs:\n{ioc_text}\n\n"
        f"Write in professional incident response report style. "
        f"Focus on what happened, impact, and recommended actions."
    )

    url = f"{settings.lm_studio_url}/chat/completions"
    payload = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": "You are a senior incident response analyst writing investigation reports."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 2048,
    }

    with httpx.Client(timeout=120) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def _build_deterministic_summary(
    case: dict, findings: list[dict], iocs: list[dict]
) -> str:
    """Build a summary without LLM — structured text only."""
    lines = [f"Investigation: {case['name']}"]
    lines.append(f"Findings: {len(findings)}")

    severity_counts = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in severity_counts:
            lines.append(f"  {sev}: {severity_counts[sev]}")

    if iocs:
        lines.append(f"IOCs identified: {len(iocs)}")

    return "\n".join(lines)