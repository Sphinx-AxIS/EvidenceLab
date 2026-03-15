# PCAP Ingest Pipeline Design

**Date:** 2026-03-14
**Status:** Approved

## Summary

Add PCAP file upload to the Sphinx Ingest page. When a user uploads a `.pcap`/`.pcapng` file, the REPL container runs tshark, Suricata, and Zeek against it, then ingests all outputs into the records table. Custom Suricata rules (post-compromise LOTL detection) are ported from the RLM CI Forensics project.

## Data Flow

1. User selects `pcap` from the Ingest dropdown and uploads a PCAP file.
2. API saves file to `/app/data/pcap_uploads/{case_id}/{uuid}.pcap` (shared filesystem).
3. API creates a background task (`pcap_ingest` type) and returns immediately with a progress message.
4. Background thread sends a `pcap_convert` command to the REPL server via Unix socket.
5. REPL runs conversion:
   - **tshark** — extracts TCP stream payloads as printable ASCII → `streams.jsonl`
   - **Suricata** — runs with custom rules + config → `eve.json`
   - **Zeek** — produces conn.log, dns.log, http.log, ssl.log, etc.
6. REPL parses outputs and inserts records into the DB using existing ingest handlers.
7. Cleanup: deletes uploaded PCAP on success, keeps on failure.

Each tool runs independently — if one is unavailable (e.g., Zeek on ARM64), the others proceed.

## Record Types Produced

### Suricata (from eve.json)

| event_type | record_type |
|------------|-------------|
| alert | suricata_alert |
| http | suricata_http |
| dns | suricata_dns |
| tls | suricata_tls |
| fileinfo | suricata_fileinfo |
| flow | suricata_flow |
| smtp | suricata_smtp |
| ssh | suricata_ssh |

### Zeek (from *.log files)

| log file | record_type |
|----------|-------------|
| conn.log | zeek_conn |
| dns.log | zeek_dns |
| http.log | zeek_http |
| ssl.log | zeek_ssl |
| files.log | zeek_files |
| x509.log | zeek_x509 |
| notice.log | zeek_notice |
| weird.log | zeek_weird |
| dhcp.log | zeek_dhcp |
| smtp.log | zeek_smtp |
| ssh.log | zeek_ssh |
| rdp.log | zeek_rdp |
| pe.log | zeek_pe |
| dpd.log | zeek_dpd |
| ntp.log | zeek_ntp |
| software.log | zeek_software |

### tshark

| output | record_type |
|--------|-------------|
| streams.jsonl | tshark_stream |

## REPL Execution

A new `pcap_convert` command is added to the REPL server. The API sends:

```json
{"cmd": "pcap_convert", "case_id": "...", "pcap_path": "/app/data/..."}
```

The REPL server calls `sphinx.plugins.sphinx_plugin_pcap.convert.convert_pcap()`, which orchestrates all three tools and DB inserts. Progress is reported back via the response.

## Files

### New

- `config/suricata/suricata.yaml` — offline PCAP mode, EVE JSON output, file extraction, JA3
- `data/suricata-rules/rlm-post-compromise.rules` — custom LOTL detection rules
- `src/sphinx/plugins/sphinx_plugin_pcap/convert.py` — conversion logic (port of RLM convert_pcap.py)

### Modified

- `docker/Dockerfile.repl` — copy suricata.yaml and rules into container
- `src/sphinx/core/repl_server.py` — add `pcap_convert` command handler
- `src/sphinx/core/frontend.py` — handle pcap upload, save file, launch background job
- `src/sphinx/core/templates/ingest.html` — add pcap option, accept .pcap/.pcapng files
- `src/sphinx/plugins/sphinx_plugin_pcap/manifest.py` — register pcap ingest type

### No Changes Needed

- No new DB migrations — all outputs go into existing `records` table with JSONB `raw` field
- Entity extraction uses existing `extract_and_store()` from each ingest handler

## Failure Modes

- **Tool not found**: logged as warning, other tools proceed. Final summary lists which tools ran.
- **Tool crashes**: stderr captured, task marked as partial success with error details.
- **PCAP too large**: no hard limit initially; timeout on subprocess (600s per tool).
- **Upload fails**: standard HTTP error, no background job created.
- **DB insert failure**: transaction rolled back per-tool, partial results from other tools preserved.

## Audit Trail

- Background task record tracks: PCAP filename, tools run, record counts per type, errors.
- Each inserted record has `source_plugin = 'sphinx-plugin-pcap'` for traceability.
- Suricata alerts include MITRE ATT&CK technique IDs from custom rules.