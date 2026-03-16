"""Sphinx signature generator — LLM-based Sigma/Suricata rule generation from findings."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from sphinx.core.config import Settings
from sphinx.core.db import get_cursor

log = logging.getLogger(__name__)

# SID range for generated Suricata rules (avoid conflict with custom rules 9000001-9000099)
SURICATA_SID_START = 9100000


def fetch_evidence_for_finding(finding_id: int) -> tuple[dict, list[dict]]:
    """Fetch a finding and its supporting evidence records.

    Returns (finding_dict, evidence_records).
    """
    with get_cursor() as cur:
        cur.execute("SELECT * FROM findings WHERE id = %s", (finding_id,))
        finding = cur.fetchone()
        if not finding:
            return {}, []

        evidence_ids = finding.get("evidence_ids", [])
        if not evidence_ids:
            return finding, []

        cur.execute(
            "SELECT id, case_id, record_type, raw, ts::text AS ts FROM records WHERE id = ANY(%s)",
            (evidence_ids,),
        )
        records = cur.fetchall()

    return finding, records


def classify_evidence(records: list[dict]) -> list[str]:
    """Determine which rule types to generate based on evidence record types.

    Returns list of rule types: ['sigma'], ['suricata'], or ['sigma', 'suricata'].
    """
    types = {r["record_type"] for r in records}

    rule_types = []

    # Windows event logs → Sigma
    winevt_types = {"win_evt_security", "win_evt_powershell", "win_evt_sysmon",
                    "win_evt_application", "win_evt_system"}
    if types & winevt_types:
        rule_types.append("sigma")

    # Suricata/PCAP evidence → Suricata (exclude Zeek — its field names
    # are Zeek abstractions like conn_state "OTH" that don't exist on the wire)
    suricata_types = {"suricata_alert", "suricata_flow", "suricata_http", "suricata_dns",
                      "suricata_tls", "tshark_stream"}
    if types & suricata_types:
        rule_types.append("suricata")

    return rule_types or ["suricata"]  # default to suricata if unclear


def _next_suricata_sid() -> int:
    """Get the next available SID for generated Suricata rules."""
    with get_cursor() as cur:
        cur.execute(
            "SELECT COALESCE(MAX(sid), %s) AS max_sid FROM detection_rules WHERE rule_type = 'suricata'",
            (SURICATA_SID_START - 1,),
        )
        return cur.fetchone()["max_sid"] + 1


def _call_llm(settings: Settings, system_prompt: str, user_prompt: str) -> str:
    """Single-shot LLM call. Returns content string."""
    url = f"{settings.lm_studio_url}/chat/completions"
    payload = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 4096,
    }

    with httpx.Client(timeout=180) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def generate_sigma_rule(
    settings: Settings,
    finding: dict,
    evidence_records: list[dict],
) -> dict[str, Any]:
    """Generate a Sigma rule from a finding and its evidence.

    Returns dict with title, description, rule_content.
    """
    # Build evidence context — include record types and sample data
    evidence_summary = []
    for r in evidence_records[:10]:  # limit context size
        raw = r["raw"] if isinstance(r["raw"], dict) else {}
        evidence_summary.append({
            "record_type": r["record_type"],
            "record_id": r["id"],
            "data": {k: v for k, v in list(raw.items())[:30]},  # limit fields
        })

    system_prompt = (
        "You are a detection engineer specializing in Sigma rules. "
        "You write Sigma rules in proper YAML format following the Sigma specification. "
        "Rules must detect BEHAVIORAL patterns, NOT specific indicators of compromise. "
        "Do NOT use specific IP addresses, domain names, file hashes, or usernames as detection criteria. "
        "Instead, focus on techniques, command patterns, process relationships, and event sequences."
    )

    user_prompt = (
        f"## Finding\n"
        f"Title: {finding.get('title', '')}\n"
        f"Body: {finding.get('body', '')[:2000]}\n"
        f"Severity: {finding.get('severity', 'medium')}\n\n"
        f"## Supporting Evidence (Windows Event Logs)\n"
        f"```json\n{json.dumps(evidence_summary, indent=2, default=str)[:6000]}\n```\n\n"
        f"## MITRE ATT&CK (pre-verified, use these exact IDs)\n"
        f"{', '.join(finding.get('mitre_ids', [])) or 'None identified'}\n\n"
        f"## Instructions\n"
        f"Generate a Sigma rule in YAML format that detects the behavioral pattern "
        f"observed in this finding. The rule should:\n"
        f"1. Use proper Sigma YAML with: title, id (UUID), status, description, "
        f"logsource, detection, condition, level, tags\n"
        f"2. Detect the BEHAVIOR, not specific IOCs\n"
        f"3. Use field names that match the Windows event log fields in the evidence\n"
        f"4. Be general enough to catch similar attacks, not just this specific instance\n"
        f"5. In the tags section, use ONLY the MITRE IDs listed above (e.g. attack.t1070.006) — do NOT use other IDs\n\n"
        f"Return ONLY the Sigma rule YAML, no other text."
    )

    content = _call_llm(settings, system_prompt, user_prompt)

    # Extract YAML from response (strip markdown fences if present)
    rule_content = content.strip()
    if rule_content.startswith("```"):
        lines = rule_content.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        rule_content = "\n".join(lines).strip()

    return {
        "title": None,  # set by caller with case context
        "description": finding.get("body", "")[:500],
        "rule_content": rule_content,
    }


def generate_suricata_rule(
    settings: Settings,
    finding: dict,
    evidence_records: list[dict],
) -> dict[str, Any]:
    """Generate a Suricata rule from a finding and its evidence.

    Returns dict with title, description, rule_content, sid.
    Only Suricata and tshark evidence is included — Zeek records are excluded
    because Zeek field names (conn_state, service labels, etc.) are Zeek
    abstractions that don't exist in raw network packets.
    """
    sid = _next_suricata_sid()

    # Filter to only Suricata + tshark evidence (exclude Zeek)
    suricata_evidence = [
        r for r in evidence_records
        if r["record_type"].startswith("suricata_") or r["record_type"] == "tshark_stream"
    ]

    # Build evidence context
    evidence_summary = []
    for r in suricata_evidence[:10]:
        raw = r["raw"] if isinstance(r["raw"], dict) else {}
        evidence_summary.append({
            "record_type": r["record_type"],
            "record_id": r["id"],
            "data": {k: v for k, v in list(raw.items())[:30]},
        })

    system_prompt = (
        "You are a detection engineer specializing in Suricata IDS rules. "
        "You write Suricata rules following the Suricata rule syntax specification. "
        "Rules must detect BEHAVIORAL patterns, NOT specific indicators of compromise. "
        "Do NOT use specific IP addresses, domain names, file hashes as match criteria. "
        "Instead, focus on protocol anomalies, payload patterns, traffic behaviors, "
        "and command sequences that indicate malicious activity.\n\n"
        "CRITICAL: Suricata inspects raw network packets. You can ONLY match content "
        "that is visible on the wire (in packet payloads). Do NOT reference Zeek field "
        "names (conn_state, service labels like 'OTH', 'SF', 'S0'), host-level artifacts "
        "(file paths, registry keys, process names), or any data that only exists in "
        "parsed/processed log output. If the evidence shows command strings from tshark "
        "stream reconstructions (payload_printable), those ARE wire-visible and can be "
        "matched with content/pcre. Suricata alerts and flow metadata show what Suricata "
        "already detected — use them to understand the traffic pattern, then write rules "
        "to detect the underlying behavior."
    )

    user_prompt = (
        f"## Finding\n"
        f"Title: {finding.get('title', '')}\n"
        f"Body: {finding.get('body', '')[:2000]}\n"
        f"Severity: {finding.get('severity', 'medium')}\n\n"
        f"## Supporting Evidence (Suricata alerts/flows + tshark stream payloads)\n"
        f"The evidence below comes from Suricata IDS and tshark TCP stream reconstruction.\n"
        f"tshark payload_printable fields contain actual wire content that can be matched.\n"
        f"Suricata alerts show what was already detected — use them for context.\n\n"
        f"```json\n{json.dumps(evidence_summary, indent=2, default=str)[:6000]}\n```\n\n"
        f"## MITRE ATT&CK (pre-verified, use these exact IDs)\n"
        f"{', '.join(finding.get('mitre_ids', [])) or 'None identified'}\n\n"
        f"## Instructions\n"
        f"Generate one or more Suricata rules that detect the behavioral pattern "
        f"observed in this finding. Each rule must:\n"
        f"1. Use proper Suricata syntax: action proto src_ip src_port -> dst_ip dst_port (options)\n"
        f"2. Use SID starting at {sid} (increment for additional rules)\n"
        f"3. Use $HOME_NET and $EXTERNAL_NET variables, not literal IPs\n"
        f"4. Include: msg, content/pcre matchers, classtype, sid, rev:1\n"
        f"5. Use the MITRE IDs listed above in metadata keyword (e.g. metadata:mitre_attack T1070.003;) — do NOT use reference:mitre_attack\n"
        f"6. ONLY match content visible in raw packets (payload strings, protocol fields)\n"
        f"7. Do NOT try to match Zeek labels, host artifacts, or parsed log fields\n"
        f"8. Encrypted protocols (SSH, TLS): you can match the handshake/banner but NOT session content\n\n"
        f"Example of a well-formed rule:\n"
        f"alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"SPHINX Suspicious HISTFILE Unset via Remote Shell\"; "
        f"flow:to_server; content:\"unset HISTFILE\"; classtype:trojan-activity; "
        f"sid:9100099; rev:1; metadata:mitre_attack T1070.003;)\n\n"
        f"Return ONLY the Suricata rule(s), one per line, no other text."
    )

    content = _call_llm(settings, system_prompt, user_prompt)

    # Clean up response
    rule_content = content.strip()
    if rule_content.startswith("```"):
        lines = rule_content.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        rule_content = "\n".join(lines).strip()

    return {
        "title": None,  # set by caller with case context
        "description": finding.get("body", "")[:500],
        "rule_content": rule_content,
        "sid": sid,
    }


def generate_rules_for_findings(
    settings: Settings,
    finding_ids: list[int],
    case_id: str,
) -> list[dict]:
    """Generate detection rules for a list of nominated findings.

    Returns list of created detection_rule dicts.
    """
    created_rules = []

    # Snapshot case name for provenance
    case_name = ""
    with get_cursor() as cur:
        cur.execute("SELECT name FROM cases WHERE id = %s", (case_id,))
        row = cur.fetchone()
        if row:
            case_name = row["name"]

    for fid in finding_ids:
        finding, evidence = fetch_evidence_for_finding(fid)
        if not finding:
            log.warning("Finding %d not found, skipping", fid)
            continue

        rule_types = classify_evidence(evidence)

        for rule_type in rule_types:
            try:
                if rule_type == "sigma":
                    result = generate_sigma_rule(settings, finding, evidence)
                else:
                    result = generate_suricata_rule(settings, finding, evidence)

                # Build title from case name + finding ID
                rule_title = f"{case_name}_finding-{fid}" if case_name else f"finding-{fid}"

                # Store in DB
                with get_cursor() as cur:
                    cur.execute(
                        """INSERT INTO detection_rules
                           (case_id, case_name, finding_id, rule_type, status, title, description,
                            rule_content, evidence_ids, mitre_ids, sid)
                           VALUES (%s, %s, %s, %s, 'pending_review', %s, %s, %s, %s, %s, %s)
                           RETURNING *""",
                        (
                            case_id,
                            case_name,
                            fid,
                            rule_type,
                            rule_title,
                            result.get("description", ""),
                            result["rule_content"],
                            finding.get("evidence_ids", []),
                            finding.get("mitre_ids", []),
                            result.get("sid"),
                        ),
                    )
                    rule = cur.fetchone()
                    cur.connection.commit()

                created_rules.append(rule)
                log.info("Generated %s rule for finding %d: %s", rule_type, fid, result["title"][:60])

            except Exception as e:
                log.error("Failed to generate %s rule for finding %d: %s", rule_type, fid, e)

    return created_rules


def _rebuild_suricata_rules_file(rules_dir: str = "/app/data/suricata-rules") -> None:
    """Rebuild sphinx-generated.rules from all deployed Suricata rules in the DB.

    This ensures the file always matches the current state of deployed rules,
    handling edits, re-deployments, and deletions cleanly.
    """
    rules_path = Path(rules_dir) / "sphinx-generated.rules"
    rules_path.parent.mkdir(parents=True, exist_ok=True)

    with get_cursor() as cur:
        cur.execute(
            """SELECT id, finding_id, title, rule_content, created_at::text AS created_at
               FROM detection_rules
               WHERE rule_type = 'suricata' AND status = 'deployed'
               ORDER BY sid NULLS LAST, id"""
        )
        deployed = cur.fetchall()

    lines = [
        "# ==========================================================================",
        "# Sphinx AI — Auto-Generated Suricata Rules",
        "# Rebuilt from deployed detection_rules in database",
        "# ==========================================================================",
        "",
    ]

    for rule in deployed:
        # Use only the first line of the title (may contain multi-line markdown)
        title_line = rule["title"].split("\n")[0].strip()[:100]
        lines.append(f"# Rule ID: {rule['id']} | Finding: {rule['finding_id']} | {title_line}")
        lines.append(rule["rule_content"])
        lines.append("")

    rules_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.info("Rebuilt %s with %d deployed rules", rules_path, len(deployed))


def deploy_suricata_rule(rule_id: int, rules_dir: str = "/app/data/suricata-rules") -> bool:
    """Deploy an approved Suricata rule.

    Marks the rule as deployed in the DB, then rebuilds the entire
    sphinx-generated.rules file from all deployed rules. This handles
    initial deployment, re-deployment after edits, and avoids duplicates.
    """
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM detection_rules WHERE id = %s AND rule_type = 'suricata'",
            (rule_id,),
        )
        rule = cur.fetchone()
        if not rule:
            return False
        if rule["status"] not in ("approved", "deployed"):
            return False

    with get_cursor() as cur:
        cur.execute(
            "UPDATE detection_rules SET status = 'deployed', updated_at = now() WHERE id = %s",
            (rule_id,),
        )
        cur.connection.commit()

    _rebuild_suricata_rules_file(rules_dir)
    return True


# ---------------------------------------------------------------------------
# Sigma compilation and execution
# ---------------------------------------------------------------------------

def compile_sigma_rule(rule_id: int) -> bool:
    """Compile a Sigma rule to SQL using pySigma and mark as deployed.

    The compiled SQL targets the records table's raw JSONB column using
    PostgreSQL JSONB operators, allowing it to run against ingested
    Windows event log data.
    """
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM detection_rules WHERE id = %s AND rule_type = 'sigma'",
            (rule_id,),
        )
        rule = cur.fetchone()
        if not rule:
            return False

    rule_yaml = rule["rule_content"]

    try:
        from sigma.rule import SigmaRule
        from sigma.backends.sqlite import SQLiteBackend
        from sigma.pipelines.base import Pipeline

        sigma_rule = SigmaRule.from_yaml(rule_yaml)

        # Use SQLite backend (closest to PostgreSQL for basic queries).
        # We post-process the output to target our JSONB structure.
        backend = SQLiteBackend()
        sql_queries = backend.convert_rule(sigma_rule)

        if not sql_queries:
            log.warning("Sigma compilation produced no SQL for rule %d", rule_id)
            return False

        # Convert to PostgreSQL JSONB query targeting the records table.
        # The SQLite backend produces WHERE clauses we can adapt.
        compiled = _adapt_sigma_sql(sql_queries[0], rule)

        with get_cursor() as cur:
            cur.execute(
                """UPDATE detection_rules
                   SET compiled_sql = %s, status = 'deployed', updated_at = now()
                   WHERE id = %s""",
                (compiled, rule_id),
            )
            cur.connection.commit()

        log.info("Compiled and deployed Sigma rule %d", rule_id)
        return True

    except ImportError:
        log.warning("pySigma not installed — compiling Sigma rule %d with basic JSONB translation", rule_id)
        # Fallback: basic YAML-to-SQL translation without pySigma
        compiled = _basic_sigma_to_sql(rule_yaml, rule)
        if compiled:
            with get_cursor() as cur:
                cur.execute(
                    """UPDATE detection_rules
                       SET compiled_sql = %s, status = 'deployed', updated_at = now()
                       WHERE id = %s""",
                    (compiled, rule_id),
                )
                cur.connection.commit()
            return True
        return False

    except Exception as e:
        log.error("Sigma compilation failed for rule %d: %s", rule_id, e)
        return False


def _adapt_sigma_sql(sqlite_sql: str, rule: dict) -> str:
    """Adapt SQLite-backend Sigma SQL to PostgreSQL JSONB query on the records table."""
    # Wrap as a query against the records table JSONB column
    return (
        f"-- Sigma rule: {rule['title']}\n"
        f"-- Rule ID: {rule['id']}\n"
        f"SELECT id, case_id, record_type, ts, raw\n"
        f"FROM records\n"
        f"WHERE record_type LIKE 'win_evt_%'\n"
        f"  AND ({sqlite_sql})"
    )


def _basic_sigma_to_sql(rule_yaml: str, rule: dict) -> str:
    """Basic Sigma YAML → SQL fallback when pySigma is not available.

    Parses the detection section and generates JSONB WHERE clauses.
    """
    import yaml

    try:
        sigma = yaml.safe_load(rule_yaml)
    except Exception:
        return ""

    detection = sigma.get("detection", {})
    condition = detection.get("condition", "selection")

    # Build WHERE clauses from selection
    selection = detection.get("selection", {})
    if not selection:
        return ""

    clauses = []
    for field, value in selection.items():
        # Map Sigma field names to JSONB access
        # Handle EventData fields specially
        if "." in field:
            parts = field.split(".")
            jsonb_path = "->".join(f"'{p}'" for p in parts[:-1])
            jsonb_access = f"raw->{jsonb_path}->>'{parts[-1]}'"
        else:
            jsonb_access = f"raw->>'{field}'"

        if isinstance(value, list):
            # OR list
            vals = ", ".join(f"'{v}'" for v in value)
            clauses.append(f"{jsonb_access} IN ({vals})")
        elif isinstance(value, str) and ("*" in value or "?" in value):
            # Wildcard → ILIKE
            like_val = value.replace("*", "%").replace("?", "_")
            clauses.append(f"{jsonb_access} ILIKE '{like_val}'")
        else:
            clauses.append(f"{jsonb_access} = '{value}'")

    if not clauses:
        return ""

    # Handle basic conditions
    if "and" in condition.lower() or "all of" in condition.lower():
        where = " AND ".join(clauses)
    else:
        where = " OR ".join(clauses)

    # Determine logsource → record_type filter
    logsource = sigma.get("logsource", {})
    product = logsource.get("product", "")
    service = logsource.get("service", "")
    category = logsource.get("category", "")

    type_filter = "record_type LIKE 'win_evt_%'"
    if service == "security":
        type_filter = "record_type = 'win_evt_security'"
    elif service == "powershell":
        type_filter = "record_type = 'win_evt_powershell'"
    elif service == "sysmon":
        type_filter = "record_type = 'win_evt_sysmon'"
    elif category == "process_creation":
        type_filter = "record_type IN ('win_evt_sysmon', 'win_evt_security')"

    return (
        f"-- Sigma rule: {rule.get('title', 'Untitled')}\n"
        f"-- Rule ID: {rule.get('id', '?')}\n"
        f"SELECT id, case_id, record_type, ts, raw\n"
        f"FROM records\n"
        f"WHERE {type_filter}\n"
        f"  AND ({where})"
    )


def run_sigma_rules_on_case(case_id: str) -> list[dict]:
    """Run all deployed Sigma rules against a case's Windows event log records.

    Returns list of matches: [{rule_id, rule_title, record_id, record_type, ts}]
    """
    matches = []

    with get_cursor() as cur:
        # Get all deployed Sigma rules with compiled SQL
        cur.execute(
            """SELECT id, title, compiled_sql
               FROM detection_rules
               WHERE rule_type = 'sigma' AND status = 'deployed'
                 AND compiled_sql IS NOT NULL AND compiled_sql != ''"""
        )
        rules = cur.fetchall()

        for rule in rules:
            try:
                # Scope the compiled SQL to this case
                scoped_sql = rule["compiled_sql"] + f"\n  AND case_id = '{case_id}'"
                cur.execute(scoped_sql)
                hits = cur.fetchall()

                for hit in hits:
                    matches.append({
                        "rule_id": rule["id"],
                        "rule_title": rule["title"],
                        "record_id": hit["id"],
                        "record_type": hit["record_type"],
                        "ts": str(hit["ts"]) if hit.get("ts") else None,
                    })

                if hits:
                    log.info("Sigma rule %d (%s) matched %d records in case %s",
                             rule["id"], rule["title"], len(hits), case_id)
            except Exception as e:
                log.warning("Sigma rule %d failed on case %s: %s", rule["id"], case_id, e)

    return matches
