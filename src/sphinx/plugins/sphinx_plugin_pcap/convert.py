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
import re
import shutil
import subprocess
import time
from pathlib import Path
import tempfile
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


def _infer_stream_roles(
    frame_payloads: list[dict[str, Any]],
    fallback_src_ip: str,
    fallback_src_port: str,
    fallback_dst_ip: str,
    fallback_dst_port: str,
) -> dict[str, str]:
    """Infer client/server roles for a tshark stream when a well-known service port is visible.

    tshark stream extraction groups payload-bearing packets from both directions into one
    stream record. The top-level src/dst fields therefore reflect whichever payload-bearing
    packet appeared first, not a stable client/server direction. This helper derives canonical
    roles from the observed service port whenever possible.
    """
    service_ports = {"20", "21", "22", "23", "25", "53", "80", "110", "123", "143", "389", "443", "445", "587", "993", "995"}

    def _is_service_port(port: str) -> bool:
        return port in service_ports

    def _is_ephemeral(port: str) -> bool:
        try:
            return int(port) >= 1024
        except Exception:
            return False

    for frame in frame_payloads:
        src_ip = str(frame.get("src_ip") or "")
        dst_ip = str(frame.get("dst_ip") or "")
        src_port = str(frame.get("src_port") or "")
        dst_port = str(frame.get("dst_port") or "")
        if _is_service_port(dst_port) and (_is_ephemeral(src_port) or not _is_service_port(src_port)):
            return {
                "client_ip": src_ip,
                "client_port": src_port,
                "server_ip": dst_ip,
                "server_port": dst_port,
                "service_port": dst_port,
                "service_side": "dst",
            }
        if _is_service_port(src_port) and (_is_ephemeral(dst_port) or not _is_service_port(dst_port)):
            return {
                "client_ip": dst_ip,
                "client_port": dst_port,
                "server_ip": src_ip,
                "server_port": src_port,
                "service_port": src_port,
                "service_side": "src",
            }

    return {
        "client_ip": fallback_src_ip,
        "client_port": fallback_src_port,
        "server_ip": fallback_dst_ip,
        "server_port": fallback_dst_port,
        "service_port": "",
        "service_side": "",
    }


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
    rule_file: str | None = None,
) -> subprocess.CompletedProcess:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not config_path:
        config_path = _find_suricata_config()

    cmd = [suri_bin, "-r", str(pcap_path.resolve()), "-l", str(output_dir)]
    if config_path:
        cmd += ["-c", config_path]
    if rule_file:
        cmd += ["-S", rule_file]
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


def _extract_rule_identity(rule_content: str) -> tuple[str | None, str | None]:
    sid_match = re.search(r"\bsid\s*:\s*(\d+)\s*;", rule_content)
    msg_match = re.search(r'msg\s*:\s*"([^"]+)"', rule_content)
    sid = sid_match.group(1) if sid_match else None
    msg = msg_match.group(1) if msg_match else None
    return sid, msg


def _replace_rule_option(rule_content: str, option_name: str, replacement: str | None) -> str:
    pattern = re.compile(rf"{option_name}\s*:[^;]*;")
    updated = pattern.sub("", rule_content)
    updated = re.sub(r"\(\s+", "(", updated)
    if replacement:
        updated = updated.replace("(", f"({replacement} ", 1)
    updated = re.sub(r"\s+\)", " )", updated)
    return re.sub(r"\s{2,}", " ", updated).strip()


def _replace_header_direction(rule_content: str, direction: str) -> str:
    return re.sub(r"\b(any|\$[A-Z_]+|\[[^\]]+\])\s+([0-9a-zA-Z_\-$\[\],]+)\s+->\s+(any|\$[A-Z_]+|\[[^\]]+\])\s+([0-9a-zA-Z_\-$\[\],]+)\s+\(",
                  rf"\1 \2 {direction} \3 \4 (", rule_content, count=1)


def _replace_header(rule_content: str, src_net: str, src_port: str, direction: str, dst_net: str, dst_port: str) -> str:
    return re.sub(
        r"\b(any|\$[A-Z_]+|\[[^\]]+\])\s+([0-9a-zA-Z_\-$\[\],]+)\s+(?:->|<>)\s+(any|\$[A-Z_]+|\[[^\]]+\])\s+([0-9a-zA-Z_\-$\[\],]+)\s+\(",
        f"{src_net} {src_port} {direction} {dst_net} {dst_port} (",
        rule_content,
        count=1,
    )


def _remove_flow_keyword(rule_content: str, keyword: str) -> str:
    pattern = re.compile(rf"\b{re.escape(keyword)}\b,?")
    updated = pattern.sub("", rule_content)
    updated = re.sub(r",\s*,", ",", updated)
    updated = re.sub(r"flow:\s*,", "flow:", updated)
    updated = updated.replace(",;", ";")
    updated = updated.replace("flow:;", "")
    return re.sub(r"\s{2,}", " ", updated).strip()


def _extract_probe_anchor(rule_content: str) -> str | None:
    pcre_match = re.search(r'pcre\s*:\s*"/(.+?)/[A-Za-z]*"', rule_content)
    if pcre_match:
        pattern = pcre_match.group(1)
        tokens = re.findall(r"[A-Za-z0-9_./-]+", pattern)
        if tokens:
            return max(tokens, key=len)
    content_match = re.search(r'content\s*:\s*"([^"]+)"', rule_content)
    if content_match:
        return content_match.group(1)
    return None


def _run_suricata_rule_test_once(
    pcap: Path,
    normalized_rule: str,
    home_net: str | None = None,
) -> dict[str, Any]:
    suri_bin = find_suricata()
    if not suri_bin:
        return {"status": "error", "error": "Suricata is not installed in the REPL container."}

    sid, msg = _extract_rule_identity(normalized_rule)

    with tempfile.TemporaryDirectory(prefix="sphinx_rule_test_") as tmpdir:
        tmp_path = Path(tmpdir)
        rules_path = tmp_path / "candidate.rules"
        rules_path.write_text(normalized_rule + "\n", encoding="utf-8")

        output_dir = tmp_path / "suricata"
        result = run_suricata(
            suri_bin,
            pcap,
            output_dir,
            home_net=home_net,
            rule_file=str(rules_path),
        )
        eve_records = parse_eve_json(output_dir)
        alerts = eve_records.get("alert", [])

        matches = []
        for alert in alerts:
            alert_obj = alert.get("alert") or {}
            sig_id = str(alert_obj.get("signature_id") or "")
            sig_msg = str(alert_obj.get("signature") or "")
            if sid and sig_id == sid:
                matches.append(alert)
                continue
            if not sid and msg and sig_msg == msg:
                matches.append(alert)

        sample_matches = []
        for alert in matches[:5]:
            alert_obj = alert.get("alert") or {}
            sample_matches.append({
                "timestamp": str(alert.get("timestamp") or ""),
                "src_ip": str(alert.get("src_ip") or ""),
                "src_port": str(alert.get("src_port") or ""),
                "dest_ip": str(alert.get("dest_ip") or ""),
                "dest_port": str(alert.get("dest_port") or ""),
                "signature": str(alert_obj.get("signature") or ""),
                "severity": str(alert_obj.get("severity") or ""),
            })

        status = "ok" if result.returncode == 0 else "partial"
        return {
            "status": status,
            "match_count": len(matches),
            "sample_matches": sample_matches,
            "sid": sid or "",
            "msg": msg or "",
            "stderr": (result.stderr or "")[:4000],
            "exit_code": result.returncode,
            "normalized_rule": normalized_rule,
        }


def _build_suricata_probe_variants(normalized_rule: str) -> list[dict[str, str]]:
    anchor = _extract_probe_anchor(normalized_rule)
    probes: list[dict[str, str]] = []
    if not anchor:
        return probes

    literal_anchor = re.sub(r'[^A-Za-z0-9_./-]+', "", anchor)
    if literal_anchor:
        probes.append({
            "label": f'Literal anchor content "{literal_anchor}"',
            "reason": "Checks whether a simpler literal content clause can match the stream at all.",
            "rule": _replace_rule_option(normalized_rule, "pcre", f'content:"{literal_anchor}";'),
        })
        probes.append({
            "label": f'Relaxed PCRE /{literal_anchor}/si',
            "reason": "Checks whether the core token appears anywhere in the inspected stream buffer.",
            "rule": _replace_rule_option(normalized_rule, "pcre", f'pcre:"/{literal_anchor}/si";'),
        })

    probes.append({
        "label": "Without only_stream",
        "reason": "Checks whether the match is being missed because the draft is restricted to the stream buffer only.",
        "rule": _remove_flow_keyword(normalized_rule, "only_stream"),
    })
    probes.append({
        "label": "Without directional flow constraint",
        "reason": "Checks whether the current to_client/to_server assumption is wrong for this PCAP.",
        "rule": _remove_flow_keyword(_remove_flow_keyword(normalized_rule, "to_client"), "to_server"),
    })
    probes.append({
        "label": "Bidirectional header",
        "reason": "Checks whether the alert only appears when direction is allowed either way.",
        "rule": _replace_header_direction(normalized_rule, "<>"),
    })
    probes.append({
        "label": "Destination port 21",
        "reason": "Checks whether the service port belongs on the destination side instead of the source side.",
        "rule": _replace_header(normalized_rule, "any", "any", "->", "any", "21"),
    })
    probes.append({
        "label": "Source port 21",
        "reason": "Checks whether the service port belongs on the source side instead of the destination side.",
        "rule": _replace_header(normalized_rule, "any", "21", "->", "any", "any"),
    })
    if literal_anchor:
        broad_probe = _replace_rule_option(normalized_rule, "pcre", f'content:"{literal_anchor}";')
        broad_probe = _replace_rule_option(broad_probe, "flow", None)
        broad_probe = _replace_header(broad_probe, "any", "any", "<>", "any", "any")
        probes.append({
            "label": f'Broad any-any literal "{literal_anchor}"',
            "reason": "Checks whether Suricata can see the core token anywhere in the PCAP without header or flow constraints.",
            "rule": broad_probe,
        })
        dst_to_server = _replace_rule_option(normalized_rule, "pcre", f'content:"{literal_anchor}";')
        dst_to_server = _replace_rule_option(dst_to_server, "flow", "flow:established,to_server;")
        dst_to_server = _replace_header(dst_to_server, "any", "any", "->", "any", "21")
        probes.append({
            "label": "Destination port 21 + to_server literal",
            "reason": "Checks the common client-to-service case with the service port on the destination side and a literal content match.",
            "rule": dst_to_server,
        })
        src_to_client = _replace_rule_option(normalized_rule, "pcre", f'content:"{literal_anchor}";')
        src_to_client = _replace_rule_option(src_to_client, "flow", "flow:established,to_client;")
        src_to_client = _replace_header(src_to_client, "any", "21", "->", "any", "any")
        probes.append({
            "label": "Source port 21 + to_client literal",
            "reason": "Checks the common service-to-client response case with the service port on the source side and a literal content match.",
            "rule": src_to_client,
        })
        dst_no_flow = _replace_rule_option(normalized_rule, "pcre", f'content:"{literal_anchor}";')
        dst_no_flow = _replace_rule_option(dst_no_flow, "flow", None)
        dst_no_flow = _replace_header(dst_no_flow, "any", "any", "->", "any", "21")
        probes.append({
            "label": "Destination port 21 literal without flow",
            "reason": "Checks whether the service port belongs on the destination side but the flow state/direction keywords are too restrictive.",
            "rule": dst_no_flow,
        })
        src_no_flow = _replace_rule_option(normalized_rule, "pcre", f'content:"{literal_anchor}";')
        src_no_flow = _replace_rule_option(src_no_flow, "flow", None)
        src_no_flow = _replace_header(src_no_flow, "any", "21", "->", "any", "any")
        probes.append({
            "label": "Source port 21 literal without flow",
            "reason": "Checks whether the service port belongs on the source side but the flow state/direction keywords are too restrictive.",
            "rule": src_no_flow,
        })
    return probes


def test_suricata_rule(
    pcap_path: str,
    rule_content: str,
    home_net: str | None = None,
) -> dict[str, Any]:
    """Run a draft Suricata rule against a PCAP and summarize matches."""
    pcap = Path(pcap_path)
    if not pcap.is_file():
        return {"status": "error", "error": f"PCAP file not found: {pcap_path}"}

    suri_bin = find_suricata()
    if not suri_bin:
        return {"status": "error", "error": "Suricata is not installed in the REPL container."}

    if not rule_content.strip():
        return {"status": "error", "error": "Rule content is empty."}

    from sphinx.core.sig_generator import normalize_suricata_rule
    normalized_rule = normalize_suricata_rule(rule_content)
    base_result = _run_suricata_rule_test_once(pcap, normalized_rule, home_net=home_net)
    base_result["pcap_file"] = pcap.name

    if base_result.get("status") == "error":
        return base_result

    probes = []
    if base_result.get("match_count", 0) == 0:
        from sphinx.core.sig_generator import normalize_suricata_rule
        for probe in _build_suricata_probe_variants(normalized_rule):
            probe_rule = normalize_suricata_rule(probe["rule"])
            probe_result = _run_suricata_rule_test_once(pcap, probe_rule, home_net=home_net)
            probes.append({
                "label": probe["label"],
                "reason": probe["reason"],
                "match_count": probe_result.get("match_count", 0),
                "status": probe_result.get("status", "error"),
                "exit_code": probe_result.get("exit_code", -1),
                "rule": probe_rule,
                "stderr": probe_result.get("stderr", ""),
            })
    base_result["probe_results"] = probes
    return base_result


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
        "-e", "frame.number",
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
        if len(parts) < 8:
            continue
        try:
            stream_idx = int(parts[0])
        except (ValueError, IndexError):
            continue

        if stream_idx not in streams:
            streams[stream_idx] = {
                "stream_index": stream_idx,
                "first_ts": parts[2],
                "last_ts": parts[2],
                "src_ip": parts[3],
                "dst_ip": parts[4],
                "src_port": parts[5],
                "dst_port": parts[6],
                "hex_parts": [],
                "frame_numbers": [],
                "frame_payloads": [],
                "packet_count": 0,
            }

        s = streams[stream_idx]
        s["last_ts"] = parts[2]
        s["packet_count"] += 1
        frame_number = parts[1].strip()
        if frame_number:
            try:
                s["frame_numbers"].append(int(frame_number))
            except ValueError:
                pass
        hex_data = parts[7].replace(":", "") if len(parts) > 7 and parts[7] else ""
        if hex_data:
            s["hex_parts"].append(hex_data)
            frame_ascii, frame_printable_count = _hex_to_printable(hex_data)
            s["frame_payloads"].append({
                "frame_number": int(frame_number) if frame_number.isdigit() else frame_number,
                "ts": parts[2],
                "src_ip": parts[3],
                "dst_ip": parts[4],
                "src_port": parts[5],
                "dst_port": parts[6],
                "payload_bytes": len(hex_data) // 2,
                "printable_chars": frame_printable_count,
                "payload_printable": frame_ascii[:512],
            })

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
        roles = _infer_stream_roles(
            s["frame_payloads"],
            s["src_ip"],
            s["src_port"],
            s["dst_ip"],
            s["dst_port"],
        )

        records.append({
            "stream_index": idx,
            "src_ip": s["src_ip"],
            "dst_ip": s["dst_ip"],
            "src_port": s["src_port"],
            "dst_port": s["dst_port"],
            "client_ip": roles["client_ip"],
            "client_port": roles["client_port"],
            "server_ip": roles["server_ip"],
            "server_port": roles["server_port"],
            "service_port": roles["service_port"],
            "service_side": roles["service_side"],
            "proto": "tcp",
            "first_ts": s["first_ts"],
            "last_ts": s["last_ts"],
            "packet_count": s["packet_count"],
            "payload_bytes": total_bytes,
            "printable_chars": printable_count,
            "printable_ratio": round(ratio, 3),
            "payload_printable": payload_ascii[:32000],
            "frame_numbers": s["frame_numbers"],
            "frame_payloads": s["frame_payloads"][:200],
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
        "total_expected": 0,
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
            summary["total_expected"] += sum(
                len(records)
                for event_type, records in eve_records.items()
                if SURICATA_TYPE_MAP.get(event_type)
            )
            _progress("ingesting Suricata records", pct_base + tool_weight // 2)
            for event_type, records in eve_records.items():
                record_type = SURICATA_TYPE_MAP.get(event_type)
                if not record_type:
                    continue
                try:
                    count = ingest_suricata_records(case_id, records, record_type, cur=db_cur, job_id=job_id)
                    summary["record_counts"][record_type] = count
                    total_inserted += count
                    _progress("ingesting Suricata records", pct_base + tool_weight // 2)
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

            zeek_logs = parse_zeek_logs(zeek_dir)
            summary["total_expected"] += sum(
                len(records)
                for log_type, records in zeek_logs.items()
                if ZEEK_TYPE_MAP.get(log_type)
            )
            _progress("ingesting Zeek records", pct_base + tool_weight // 2)
            for log_type, records in zeek_logs.items():
                record_type = ZEEK_TYPE_MAP.get(log_type)
                if not record_type:
                    continue
                try:
                    count = ingest_zeek_records(case_id, records, record_type, cur=db_cur, job_id=job_id)
                    summary["record_counts"][record_type] = count
                    total_inserted += count
                    _progress("ingesting Zeek records", pct_base + tool_weight // 2)
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
                summary["total_expected"] += len(stream_records)
                _progress("ingesting tshark streams", pct_base + tool_weight // 2)
                try:
                    count = ingest_tshark(case_id, stream_records, cur=db_cur, job_id=job_id)
                    summary["record_counts"]["tshark_stream"] = count
                    total_inserted += count
                    _progress("ingesting tshark streams", pct_base + tool_weight // 2)
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
