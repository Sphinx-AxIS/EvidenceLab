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

- **Evidence Ingest** -- Upload PCAPs, Windows Event Logs (.evtx), Volatility3 output or use the built in Volatility3 tool to generate the outputs from a memory image. Deterministic parsers extract structured records into PostgreSQL.
- **Suricata + Zeek + tshark** -- PCAP files are automatically processed by all three tools during ingest.
- **Detection Rules** -- Import, create, edit, and deploy Suricata and Sigma rules through the web UI. LLM can also generate rules from investigation findings.
- **RLM Investigation Loop** -- Step-bounded reasoning loop where the LLM writes and executes Python in a sandboxed REPL to investigate evidence.
- **Dashboard & Analytics** -- Pre-computed SQL analytics, entity extraction, and record browsing.
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
3. Browse ingested records from the **Records** page
4. Create an investigation task from the **Tasks** page
5. Review LLM findings and generate a report

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
| `POSTGRES_PASSWORD` | Database password | `changeme` |
| `JWT_SECRET` | Secret for signing auth tokens | `changeme-...` |
| `LM_STUDIO_URL` | LM Studio API endpoint | `http://localhost:1234/v1` |
| `LLM_MODEL` | Model name for LM Studio | `qwen2.5-coder-32b-instruct` |
| `RLM_MAX_STEPS` | Max steps per investigation task | `15` |
| `SPHINX_PORT` | Host port for the web UI | `8000` |

## Network Security Model

The Docker network topology enforces isolation:

- The **REPL** container (where LLM-generated code executes) has **no internet access** -- it can only reach the database and communicate with the API via a Unix socket.
- The **database** has **no internet access** -- only the API and REPL containers can connect.
- Only the **API** container is exposed to the host network.

## License

Private repository. All rights reserved.
