"""PCAP conversion pipeline — run tshark, Suricata, and Zeek against a PCAP file.

Ported from RLM CI Forensics ``convert_pcap.py``. Orchestrates all three
tools, parses their outputs, and ingests records into the Sphinx database
via the plugin's ingest handlers.

Called by the REPL server's ``pcap_convert`` command.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import psycopg
import psycopg.rows
from psycopg.types.json import Jsonb

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def find_zeek() -> str:
    zeek = shutil.which("zeek")
    if zeek:
        return zeek
    for candidate in ["/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek", "/usr/bin/zeek"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def find_suricata() -> str:
    suri = shutil.which("suricata")
    if suri:
        return suri
    for candidate in ["/usr/bin/suricata", "/usr/local/bin/suricata"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def find_tshark() -> str:
    ts = shutil.which("tshark")
    if ts:
        return ts
    for candidate in ["/usr/bin/tshark", "/usr/local/bin/tshark"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------

def _detect_zeek_version(zeek_bin: str) -> tuple[int, int]:
    try:
        out = subprocess.run([zeek_bin, "--version"], capture_output=True, text=True)
        for token in (out.stdout + out.stderr).split():
            if "." in token and token[0].isdigit():
                parts = token.split(".")
                return int(parts[0]), int(parts[1])
    except Exception:
        pass
    return (0, 0)


def run_zeek(zeek_bin: str, pcap_path: Path, output_dir: Path) -> subprocess.CompletedProcess:
    output_dir.mkdir(parents=True, exist_ok=True)
    major, minor = _detect_zeek_version(zeek_bin)
    log.info("Zeek version: %d.%d", major, minor)

    cmd = [zeek_bin, "-r", str(pcap_path.resolve())]
    zeek_loads = ["@load policy/protocols/conn/community-id-logging"]
    if major >= 7:
        zeek_loads.append("@load policy/tuning/json-logs")
    else:
        cmd.append("LogAscii::use_json=T")

    loader_path = output_dir / "_loader.zeek"
    loader_path.write_text("\n".join(zeek_loads) + "\n", encoding="utf-8")
    cmd.append(loader_path.name)

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(output_dir), timeout=600)
    loader_path.unlink(missing_ok=True)

    if result.stderr:
        log.warning("Zeek stderr: %s", result.stderr[:2000])
    return result


def parse_zeek_logs(log_dir: Path) -> dict[str, list[dict]]:
    """Parse all Zeek JSON log files. Returns {log_type: [records]}."""
    results: dict[str, list[dict]] = {}
    for f in sorted(log_dir.glob("*.log")):
        log_type = f.stem  # conn, dns, http, etc.
        records = []
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("#"):
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
        if records:
            results[log_type] = records
    return results


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

_SURICATA_CONFIG_PATHS = [
    "/etc/suricata/suricata.yaml",
    "/app/config/suricata/suricata.yaml",
]


def _find_suricata_config() -> str:
    for path in _SURICATA_CONFIG_PATHS:
        if os.path.isfile(path):
            return path
    return ""


def run_suricata(
    suri_bin: str, pcap_path: Path, output_dir: Path,
    config_path: str | None = None,
    home_net: str | None = None,
) -> subprocess.CompletedProcess:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not config_path:
        config_path = _find_suricata_config()

    cmd = [suri_bin, "-r", str(pcap_path.resolve()), "-l", str(output_dir)]
    if config_path:
        cmd += ["-c", config_path]
    cmd += ["--set", "outputs.0.eve-log.filename=eve.json"]

    # Case-specific HOME_NET takes priority over environment variable
    effective_home_net = home_net or os.environ.get("SURICATA_HOME_NET")
    if effective_home_net:
        cmd += ["--set", f"vars.address-groups.HOME_NET={effective_home_net}"]

    log.info("Suricata command: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.stderr:
        log.warning("Suricata stderr: %s", result.stderr[:2000])
    return result


def parse_eve_json(output_dir: Path) -> dict[str, list[dict]]:
    """Parse eve.json into {event_type: [records]}."""
    eve_path = output_dir / "eve.json"
    results: dict[str, list[dict]] = {}
    if not eve_path.is_file():
        return results

    try:
        with open(eve_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                    etype = evt.get("event_type", "unknown")
                    results.setdefault(etype, []).append(evt)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return results


# ---------------------------------------------------------------------------
# tshark — TCP stream payload extraction
# ---------------------------------------------------------------------------

def _hex_to_printable(hex_str: str) -> tuple[str, int]:
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return "", 0

    chars = []
    printable = 0
    for b in raw:
        if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09):
            chars.append(chr(b))
            if 0x20 <= b <= 0x7E:
                printable += 1
        else:
            chars.append(".")
    return "".join(chars), printable


def run_tshark_streams(
    tshark_bin: str,
    pcap_path: Path,
    output_dir: Path,
    min_printable_chars: int = 20,
    max_streams: int = 2000,
) -> list[dict]:
    """Extract TCP stream payloads. Returns list of stream records."""
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        tshark_bin, "-r", str(pcap_path.resolve()),
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.payload",
        "-Y", "tcp.len>0",
        "-E", "separator=\t",
    ]

    log.info("tshark command: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if result.returncode != 0:
        log.warning("tshark stderr: %s", result.stderr[:2000])
        return []

    # Group packets by TCP stream index
    streams: dict[int, dict] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        try:
            stream_idx = int(parts[0])
        except (ValueError, IndexError):
            continue

        if stream_idx not in streams:
            streams[stream_idx] = {
                "stream_index": stream_idx,
                "first_ts": parts[1],
                "last_ts": parts[1],
                "src_ip": parts[2],
                "dst_ip": parts[3],
                "src_port": parts[4],
                "dst_port": parts[5],
                "hex_parts": [],
                "packet_count": 0,
            }

        s = streams[stream_idx]
        s["last_ts"] = parts[1]
        s["packet_count"] += 1
        hex_data = parts[6].replace(":", "") if len(parts) > 6 and parts[6] else ""
        if hex_data:
            s["hex_parts"].append(hex_data)

    # Convert hex -> printable ASCII, filter, collect records
    records = []
    for idx in sorted(streams.keys()):
        if len(records) >= max_streams:
            break
        s = streams[idx]
        hex_str = "".join(s["hex_parts"])
        payload_ascii, printable_count = _hex_to_printable(hex_str)

        if printable_count < min_printable_chars:
            continue

        total_bytes = len(hex_str) // 2
        ratio = printable_count / total_bytes if total_bytes else 0

        records.append({
            "stream_index": idx,
            "src_ip": s["src_ip"],
            "dst_ip": s["dst_ip"],
            "src_port": s["src_port"],
            "dst_port": s["dst_port"],
            "proto": "tcp",
            "first_ts": s["first_ts"],
            "last_ts": s["last_ts"],
            "packet_count": s["packet_count"],
            "payload_bytes": total_bytes,
            "printable_chars": printable_count,
            "printable_ratio": round(ratio, 3),
            "payload_printable": payload_ascii[:32000],
        })

    # Also write streams.jsonl for reference
    streams_path = output_dir / "streams.jsonl"
    with open(streams_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    log.info("tshark -> %d TCP streams with printable content (from %d total)",
             len(records), len(streams))
    return records


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# Map Suricata event_type -> Sphinx record_type
SURICATA_TYPE_MAP = {
    "alert": "suricata_alert",
    "http": "suricata_http",
    "dns": "suricata_dns",
    "tls": "suricata_tls",
    "fileinfo": "suricata_fileinfo",
    "flow": "suricata_flow",
    "smtp": "suricata_smtp",
    "ssh": "suricata_ssh",
}

# Map Zeek log stem -> Sphinx record_type
ZEEK_TYPE_MAP = {
    "conn": "zeek_conn",
    "dns": "zeek_dns",
    "http": "zeek_http",
    "ssl": "zeek_ssl",
    "files": "zeek_files",
    "x509": "zeek_x509",
    "notice": "zeek_notice",
    "weird": "zeek_weird",
    "dhcp": "zeek_dhcp",
    "smtp": "zeek_smtp",
    "ssh": "zeek_ssh",
    "rdp": "zeek_rdp",
    "pe": "zeek_pe",
    "dpd": "zeek_dpd",
    "ntp": "zeek_ntp",
    "software": "zeek_software",
}


def _update_job_progress(
    db_conn, job_id: int | None, summary: dict, status: str | None = None,
) -> None:
    """Write incremental progress to the background_jobs row.

    If *status* is provided the status column is also updated (for terminal states).
    """
    if not job_id:
        return
    try:
        with db_conn.cursor() as cur:
            if status:
                cur.execute(
                    "UPDATE background_jobs SET status = %s, summary = %s, updated_at = now() WHERE id = %s",
                    (status, Jsonb(summary), job_id),
                )
            else:
                cur.execute(
                    "UPDATE background_jobs SET summary = %s, updated_at = now() WHERE id = %s",
                    (Jsonb(summary), job_id),
                )
            db_conn.commit()
    except Exception as e:
        log.warning("Could not update job %s progress: %s", job_id, e)


def convert_pcap(
    case_id: str,
    pcap_path: str,
    work_dir: str | None = None,
    job_id: int | None = None,
    home_net: str | None = None,
) -> dict[str, Any]:
    """Run tshark, Suricata, and Zeek against a PCAP file, ingest all outputs.

    Args:
        case_id: Sphinx case UUID.
        pcap_path: Absolute path to the PCAP file.
        work_dir: Directory for intermediate outputs. Auto-created if None.
        job_id: Optional background_jobs row ID for progress updates.
        home_net: Case-specific HOME_NET override for Suricata.

    Returns:
        Summary dict with tool statuses and record counts.
    """
    from sphinx.plugins.sphinx_plugin_pcap.ingest import (
        ingest_suricata_records,
        ingest_zeek_records,
        ingest_tshark,
    )

    pcap = Path(pcap_path)
    if not pcap.is_file():
        return {"status": "error", "error": f"PCAP file not found: {pcap_path}"}

    if work_dir:
        base_dir = Path(work_dir)
    else:
        base_dir = pcap.parent / f"_sphinx_convert_{pcap.stem}"
    base_dir.mkdir(parents=True, exist_ok=True)

    # Use direct DB connections from the REPL container. Keep the default
    # REPL DATABASE_URL read-only, and use a dedicated ingest writer DSN for
    # inserting derived records back into the case.
    ingest_db_url = os.environ.get("INGEST_DATABASE_URL") or os.environ.get(
        "DATABASE_URL",
        "postgresql://sphinx:changeme@sphinx-db:5432/sphinx",
    )
    progress_db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://sphinx:changeme@sphinx-db:5432/sphinx",
    )

    db_conn = psycopg.connect(ingest_db_url, row_factory=psycopg.rows.dict_row)
    db_cur = db_conn.cursor()
    # Separate connection for progress — never poisoned by ingest errors
    progress_conn = psycopg.connect(progress_db_url, row_factory=psycopg.rows.dict_row)

    pcap_size_mb = round(pcap.stat().st_size / (1024 * 1024), 1)

    t0 = time.time()
    summary: dict[str, Any] = {
        "pcap_file": pcap.name,
        "pcap_size_mb": pcap_size_mb,
        "tools_run": [],
        "tools_skipped": [],
        "record_counts": {},
        "errors": [],
        "stage": "initializing",
        "pct": 0,
    }

    def _progress(stage: str, pct: int) -> None:
        summary["stage"] = stage
        summary["pct"] = pct
        summary["elapsed_s"] = round(time.time() - t0, 1)
        summary["total_inserted"] = total_inserted
        _update_job_progress(progress_conn, job_id, summary)

    # --- Locate tools ---
    zeek_bin = find_zeek()
    suri_bin = find_suricata()
    tshark_bin = find_tshark()

    # Build list of active tools to compute % weights
    tools_active = []
    if suri_bin:
        tools_active.append("suricata")
    else:
        summary["tools_skipped"].append("suricata")
        log.warning("Suricata not found — skipping")
    if zeek_bin:
        tools_active.append("zeek")
    else:
        summary["tools_skipped"].append("zeek")
        log.warning("Zeek not found — skipping")
    if tshark_bin:
        tools_active.append("tshark")
    else:
        summary["tools_skipped"].append("tshark")
        log.warning("tshark not found — skipping")

    if not tools_active:
        return {"status": "error", "error": "No analysis tools found (Zeek, Suricata, tshark)"}

    # Each tool gets an equal share of 0-90%, ingesting fills to 95%, final 100%
    tool_weight = 90 // len(tools_active)
    pct_base = 0
    total_inserted = 0

    _progress("starting", 0)

    # --- Suricata ---
    if suri_bin:
        try:
            _progress("running Suricata", pct_base)
            suri_dir = base_dir / "suricata"
            result = run_suricata(suri_bin, pcap, suri_dir, home_net=home_net)
            summary["tools_run"].append("suricata")

            if result.returncode != 0:
                summary["errors"].append(f"Suricata exit code {result.returncode}")

            _progress("ingesting Suricata records", pct_base + tool_weight // 2)
            eve_records = parse_eve_json(suri_dir)
            for event_type, records in eve_records.items():
                record_type = SURICATA_TYPE_MAP.get(event_type)
                if not record_type:
                    continue
                try:
                    count = ingest_suricata_records(case_id, records, record_type, cur=db_cur, job_id=job_id)
                    summary["record_counts"][record_type] = count
                    total_inserted += count
                except Exception as e:
                    db_conn.rollback()  # clear aborted transaction state
                    summary["errors"].append(f"Suricata ingest ({record_type}): {e}")
                    log.error("Suricata ingest error (%s): %s", record_type, e)
        except Exception as e:
            summary["errors"].append(f"Suricata failed: {e}")
            log.error("Suricata failed: %s", e)
        pct_base += tool_weight

    # --- Zeek ---
    if zeek_bin:
        try:
            _progress("running Zeek", pct_base)
            zeek_dir = base_dir / "zeek"
            result = run_zeek(zeek_bin, pcap, zeek_dir)
            summary["tools_run"].append("zeek")

            if result.returncode != 0:
                summary["errors"].append(f"Zeek exit code {result.returncode}")

            _progress("ingesting Zeek records", pct_base + tool_weight // 2)
            zeek_logs = parse_zeek_logs(zeek_dir)
            for log_type, records in zeek_logs.items():
                record_type = ZEEK_TYPE_MAP.get(log_type)
                if not record_type:
                    continue
                try:
                    count = ingest_zeek_records(case_id, records, record_type, cur=db_cur, job_id=job_id)
                    summary["record_counts"][record_type] = count
                    total_inserted += count
                except Exception as e:
                    db_conn.rollback()
                    summary["errors"].append(f"Zeek ingest ({record_type}): {e}")
                    log.error("Zeek ingest error (%s): %s", record_type, e)
        except Exception as e:
            summary["errors"].append(f"Zeek failed: {e}")
            log.error("Zeek failed: %s", e)
        pct_base += tool_weight

    # --- tshark ---
    if tshark_bin:
        try:
            _progress("running tshark", pct_base)
            tshark_dir = base_dir / "tshark"
            stream_records = run_tshark_streams(tshark_bin, pcap, tshark_dir)
            summary["tools_run"].append("tshark")

            if stream_records:
                _progress("ingesting tshark streams", pct_base + tool_weight // 2)
                try:
                    count = ingest_tshark(case_id, stream_records, cur=db_cur, job_id=job_id)
                    summary["record_counts"]["tshark_stream"] = count
                    total_inserted += count
                except Exception as e:
                    db_conn.rollback()
                    summary["errors"].append(f"tshark ingest: {e}")
                    log.error("tshark ingest error: %s", e)
        except Exception as e:
            summary["errors"].append(f"tshark failed: {e}")
            log.error("tshark failed: %s", e)
        pct_base += tool_weight

    # Final summary — write terminal status directly to DB via the progress
    # connection (guaranteed healthy, independent of ingest connection).
    elapsed = time.time() - t0
    summary["total_inserted"] = total_inserted
    summary["elapsed_s"] = round(elapsed, 2)
    summary["stage"] = "complete"
    summary["pct"] = 100
    final_status = "ok" if not summary["errors"] else "partial"
    summary["status"] = final_status
    _update_job_progress(progress_conn, job_id, summary, status=final_status)

    # Clean up DB connections
    for conn in (db_cur, db_conn, progress_conn):
        try:
            conn.close()
        except Exception:
            pass

    log.info("PCAP conversion complete: %d records in %.1fs (tools: %s)",
             total_inserted, elapsed, ", ".join(summary["tools_run"]))
    return summary
