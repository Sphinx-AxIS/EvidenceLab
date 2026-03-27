# EvidenceLab

A plugin-based incident response investigation platform that combines automated evidence parsing with LLM-driven analysis. Sphinx ingests PCAP captures, Windows Event Logs, and memory forensics output, stores everything in PostgreSQL, and provides a web dashboard for analysts to investigate incidents with AI assistance.

## Architecture

Three-container Docker Compose stack:

| Container | Role | Network Access |
|-----------|------|----------------|
| **api** | FastAPI web server (port 8000) | Internal + external |
| **repl** | Sandboxed Python REPL for LLM code execution | Internal only (no internet) |
| **db** | PostgreSQL 16 with pgvector | Internal only (no internet) |

LLM inference runs on the host via [LM Studio](https://lmstudio.ai/) (OpenAI-compatible API). The REPL container calls the LLM through the host network — no API keys or cloud services required.

## Features

- **Evidence Ingest** -- Upload PCAPs, Windows Event Logs (.evtx), or Volatility3 JSON output. Deterministic parsers extract structured records into PostgreSQL while preserving source event timestamps where available.
- **Live Ingest Visibility** -- The Ingest page and Dashboard both show current background ingest jobs and progress for long-running PCAP processing.
- **Suricata + Zeek + tshark** -- PCAP files are automatically processed by all three tools during ingest.
- **Detection Rules** -- Import, create, edit, and deploy Suricata and Sigma rules through the web UI. LLM can also generate rules from investigation findings.
- **Deterministic Rule Assistance** -- Show merged detection-context tables with signature priority, field/value anchors, and case-local counts to help analysts build Sigma and Suricata rules without AI.
- **RLM Investigation Loop** -- Step-bounded reasoning loop where the LLM writes and executes Python in a sandboxed REPL to investigate evidence.
- **Dashboard & Analytics** -- Interactive hunting workspace with ATT&CK-inspired Windows starter filters, pre-computed SQL analytics, false-positive-aware entity extraction, and record browsing.
- **Windows ATT&CK Mapping Filters** -- The Analytics page can load tactic, technique, and EventID starter filters from the bundled Windows ATT&CK mapping dataset.
- **Plugin System** -- Evidence types are handled by plugins (`pcap`, `winevt`, `memory`, `threat-hunter`), each with their own ingest handlers, analytics, and prompts.
- **RBAC** -- Role-based access control (admin, case_manager, analyst) with JWT authentication. Admins can manage users, delete evidence, cases, individual tasks, and detection rules from the Admin pages.
- **Report Generation** -- Structured reports with evidence citations and MITRE ATT&CK mapping.
- **User Manual** -- Searchable in-app user manual accessible from the sidebar, covering every page and feature.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- [LM Studio](https://lmstudio.ai/) running on the host with a loaded model (e.g., `qwen2.5-coder-32b-instruct`)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Sphinx-AxIS/EvidenceLab.git
   cd EvidenceLab
   ```

2. Create your environment file:
   ```bash
   cp .env.example .env
   # Edit .env — at minimum change POSTGRES_PASSWORD and JWT_SECRET
   ```

3. Start the stack:
   ```bash
   cd docker
   docker compose up --build -d
   ```

4. Open the web UI at `http://localhost:8000`

### First Investigation

1. Create a case from the **Cases** page
2. Navigate to **Ingest** and upload a PCAP, EVTX, or Volatility JSON file
3. Hunt from the **Analytics** page using the clickable record-type cards or Windows ATT&CK starter filters
4. Open a specific result in **Records** to inspect the event context and decide whether it is detection-worthy
5. Pivot from that inspected event or packet into the guided Sigma or Suricata rule builder
6. Create an investigation task from the **Tasks** page
7. Review LLM findings and generate a report

The Suricata builder now walks the analyst through a no-AI workflow: review the normalized flow, choose a detection strategy, pick a content match style, click High/Medium/Low candidate atoms, and watch the rule preview update automatically while the full source record JSON stays visible. Payload previews are shown as escaped JSON-style strings, JSON panes are rendered as escaped literal text, high ephemeral ports are ignored by default for behavior/service-style drafts, and candidate content atoms now call out whether they were seen in a single frame or only after stream reassembly. The preview also derives header direction and `to_server`/`to_client` flow hints from the selected anchor's actual frame provenance when possible, instead of relying only on the stream-wide port summary. Because tshark stream summaries only capture the first payload-bearing packet in a stream, new `tshark_stream` records now also store canonical client/server roles inferred from the service port so the builder can show both the raw stream orientation and the more stable client/server interpretation. When EvidenceLab can tie a content anchor to specific payload-bearing frames, the displayed source/destination endpoint anchors follow that anchor-frame context rather than the coarse stream summary, and the explicit `flow:to_server` / `flow:to_client` card now uses that same active anchor context. Endpoint cards for IPs and ports are now overridable, so the analyst can swap `src`/`dst` and choose from the observed endpoint values directly inside the cards when the initial orientation needs correction. Flow cards are now overridable too, with a dropdown of common Suricata `flow` keywords so the analyst can choose the exact flow constraint to carry into the draft. In recommended mode, reassembly-dependent strings are normally rendered as resilient token-sequence PCRE, but if the builder can prove that a strong sub-token was seen wholly inside one payload-bearing frame, it prefers that packet-scoped literal instead and uses that same fallback anchor context for the cards and the preview. Single-packet literal anchors also avoid auto-adding `flow` keywords when those constraints would likely over-restrict the rule, and the default checkbox selection now starts conservatively instead of preselecting weak port or flow anchors. When an analyst explicitly checks an IP, port, or flow anchor, that selection now carries into the live draft instead of being silently overridden by inferred defaults. If no content anchor and no port anchor are selected, the preview now leaves the header at `any any -> any any` instead of silently backfilling a service port from stream summary data.

On the manual Suricata rule form, analysts can also test a draft rule against the latest uploaded PCAP for the current case before saving or deploying it. Uploaded PCAPs are retained so this replay path remains available after ingest. If the main rule returns zero matches, EvidenceLab now shows automatic probe variants to help diagnose whether the miss is caused by direction, source-vs-destination service-port placement, flow keywords, stream-only matching, the chosen content pattern, or a broader test-path issue.

## Suricata Rules

Custom detection rules live in `data/suricata-rules/`. Suricata loads all `*.rules` files from this directory automatically.

**Bundled rules:**
- `rlm-post-compromise.rules` -- Custom LOTL (living-off-the-land) post-compromise detection rules

**Adding ET Open rules:**
```bash
# On a machine with internet access:
sudo apt install suricata-update
cd data/suricata-rules
suricata-update --output . --suricata-version 7.0.10
```

Rules can also be imported into the database via the **Admin: Data** page for editing and lifecycle management through the web UI.

## Project Structure

```
EvidenceLab/
├── config/
│   └── suricata/           # Suricata config (offline PCAP mode)
├── data/
│   └── suricata-rules/     # Active Suricata rule files
├── docker/
│   ├── Dockerfile          # API container
│   ├── Dockerfile.repl     # REPL sandbox (Suricata, Zeek, tshark)
│   └── docker-compose.yml
├── docs/
│   ├── plans/              # Design documents
│   └── user_manual.md      # Searchable user manual (also served in-app)
├── sample_data/            # Example evidence files for testing
├── sql/                    # Database migrations (run at startup)
├── src/
│   └── sphinx/
│       ├── core/           # Platform core (API, auth, RLM loop, UI)
│       └── plugins/        # Evidence type plugins
├── tests/
├── .env.example
├── pyproject.toml
└── requirements.txt
```

## Configuration

Key environment variables (see `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | Database password (API container) | `changeme` |
| `REPL_DB_PASSWORD` | Database password (REPL container, restricted role) | `repl_changeme` |

PCAP conversion runs inside the isolated REPL container, but derived Suricata, Zeek, and tshark records are written back through a dedicated internal ingest connection. The interactive REPL session remains on the restricted `sphinx_repl` role.
| `JWT_SECRET` | Secret for signing auth tokens | `changeme-...` |
| `LM_STUDIO_URL` | LM Studio API endpoint | `http://localhost:1234/v1` |
| `LLM_MODEL` | Model name for LM Studio | `qwen2.5-coder-32b-instruct` |
| `RLM_MAX_STEPS` | Max steps per investigation task | `15` |
| `SPHINX_PORT` | Host port for the web UI | `8000` |

## Security Model

### Network Isolation

- The **REPL** container (where LLM-generated code executes) has **no internet access** -- it can only reach the database and communicate with the API via a Unix socket.
- The **database** has **no internet access** -- only the API and REPL containers can connect.
- Only the **API** container is exposed to the host network.

### Database Role Separation

- The **API** container connects as `sphinx` (full access) for migrations, user management, and ingest.
- The **REPL** container connects as `sphinx_repl`, a restricted PostgreSQL role with SELECT-only access to evidence tables and no access to admin tables (`users`, `case_assignments`, etc.).

### Row-Level Security (RLS)

PostgreSQL RLS policies enforce case-scoping at the database level. The REPL sets `app.readable_case_ids` at connection time, and the database ensures LLM-generated queries only return data from authorized cases.

### LLM Authentication

An `llm_agent` service account is auto-created at startup. When a task runs, a short-lived JWT (30-minute expiry) is minted, scoped to the task's case (Investigator mode) or source cases (Correlator mode).

## License

Private repository. All rights reserved.
