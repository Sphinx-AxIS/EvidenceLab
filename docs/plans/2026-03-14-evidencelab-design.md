# EvidenceLab — Design Document

**Date:** 2026-03-14
**Status:** Approved

---

## 1. Project Overview & Architecture

EvidenceLab is a simplified, plugin-based incident response investigation platform. It follows the same RLM design contract as ResilientCORE (environment-mediated reasoning, full-dataset coverage, audit-first transparency) but strips away complexity in favor of a dashboard-centered, plugin-driven architecture.

### Core Platform

The core provides:

- **Dashboard** — central hub; all navigation flows from here
- **Case management** — create, configure, close investigations
- **PostgreSQL database** — evidence storage, OCSF views, scratch tables, worklog
- **Docker REPL sandbox** — LLM code execution environment
- **RLM loop** — step-bounded investigation engine
- **Plugin loader** — discovers and activates pip-installed plugins
- **RBAC / JWT** — role-based access control at the API layer
- **Report generator** — structured output with evidence citations

### Bundled Plugins (v1)

| Plugin | Scope |
|--------|-------|
| `sphinx-plugin-pcap` | PCAP ingest (Suricata, Zeek, tshark), OCSF network views |
| `sphinx-plugin-winevt` | Windows Event Log ingest, per-channel views (Security, PowerShell, Application, System, Sysmon) |
| `sphinx-plugin-memory` | Volatility 3 output ingest, process/network/registry views |
| `sphinx-plugin-threat-hunter` | Cross-source correlation, MITRE ATT&CK mapping, IOC extraction |

### Future Plugin (noted)

| Plugin | Scope |
|--------|-------|
| `sphinx-plugin-csv-elastic` | CSV/Elastic export ingest and analytics |

---

## 2. LLM Minimization & Prompt Ownership

### Principle

Reserve LLM compute for investigative reasoning only. All ingest, analytics, search, and reporting structure use deterministic code.

### What runs without LLM

- Evidence ingest and parsing
- OCSF mapping and view creation
- Pre-computed analytics queries
- Entity extraction (regex-based IOC patterns)
- Dashboard widgets and SQL aggregations
- Report structure and formatting
- Tag taxonomy enforcement

### What requires LLM

- Investigation task execution (RLM loop)
- Hypothesis generation and iterative code writing
- Natural-language findings synthesis
- Cross-source correlation reasoning (threat-hunter plugin)

### Prompt Ownership

Prompts and LLM model instructions ship with the applicable plugin, not the core. The core platform includes only prompts for its own functions (case management, report assembly, generic REPL instructions). Each plugin's `manifest.py` declares its prompt templates, which are registered when the plugin loads.

---

## 3. RBAC & JWT Model

### Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full platform access, user management, plugin install/remove, system config |
| `case_manager` | Create/close cases, assign analysts, view all cases, manage case-level settings |
| `analyst` | View assigned cases, run investigations, create findings, generate reports |
| `llm_agent` | Scoped to single case, execute REPL code, read/write scratch tables, create worklog entries |

### JWT Claims

```json
{
  "sub": "user-id",
  "role": "analyst",
  "case_ids": ["case-001", "case-003"],
  "mode": "investigator",
  "exp": 1710460800
}
```

- `case_ids` — scopes access to specific cases (empty = all for admin/case_manager)
- `mode` — `"investigator"` (single-case) or `"correlator"` (cross-case)

### Two LLM Modes

1. **Investigator** — default per-case mode. LLM has access to one case's evidence. Standard RLM loop.
2. **Correlator** — cross-case mode. Analyst selects cases to correlate. LLM can query across selected cases. Read-only access to source cases; writes findings to a correlation case.

The analyst switches between modes on demand from the dashboard.

### Enforcement

JWT validation happens at the API layer (middleware). Every API endpoint checks:
1. Token validity and expiration
2. Role has permission for the action
3. Case ID in the request matches `case_ids` claim

The REPL sandbox receives a scoped database connection that can only access the case(s) in the JWT.

---

## 4. Plugin Manifest & Lifecycle

### Manifest Structure

Each plugin is a pip-installable Python package with a `manifest.py` at its root:

```python
# sphinx_plugin_pcap/manifest.py

MANIFEST = {
    "name": "sphinx-plugin-pcap",
    "version": "0.1.0",
    "description": "PCAP evidence: Suricata alerts, Zeek logs, tshark streams",

    "ingest_handlers": {
        "suricata_alert": "sphinx_plugin_pcap.ingest:ingest_suricata",
        "zeek_conn": "sphinx_plugin_pcap.ingest:ingest_zeek_conn",
        "zeek_dns": "sphinx_plugin_pcap.ingest:ingest_zeek_dns",
        "tshark_stream": "sphinx_plugin_pcap.ingest:ingest_tshark",
    },

    "ocsf_mappers": {
        "net_events": "sphinx_plugin_pcap.ocsf:map_net_events",
    },

    "prompts": {
        "pcap_system": "sphinx_plugin_pcap.prompts:SYSTEM_PROMPT",
        "pcap_docs": "sphinx_plugin_pcap.prompts:DOC_SECTIONS",
    },

    "precompute": [
        "sphinx_plugin_pcap.precompute:top_talkers",
        "sphinx_plugin_pcap.precompute:alert_severity_counts",
        "sphinx_plugin_pcap.precompute:protocol_distribution",
        "sphinx_plugin_pcap.precompute:connection_timeline",
    ],

    "migrations": [
        "sphinx_plugin_pcap/sql/001_pcap_views.sql",
    ],

    "dashboard_widgets": [
        "sphinx_plugin_pcap.widgets:alert_summary",
        "sphinx_plugin_pcap.widgets:top_talkers_chart",
    ],
}
```

### Lifecycle

1. **Install** — `pip install sphinx-plugin-pcap`
2. **Discover** — core scans for `sphinx_plugin_*` entry points at startup
3. **Register** — manifest is validated and handlers are registered
4. **Migrate** — plugin SQL migrations run (tracked in `plugin_migrations` table)
5. **Activate** — ingest handlers, OCSF mappers, prompts, and widgets become available
6. **Uninstall** — `pip uninstall`; migrations are not auto-rolled-back (admin decision)

---

## 5. Dashboard Layout

The dashboard is the single entry point. All navigation flows from it.

### Widget Areas

```
+------------------------------------------------------+
|  [Case Selector ▼]   [Mode: Investigator | Correlator]|
+------------------------------------------------------+
|                                                      |
|  Local/Victim Networks    |    Case Notes            |
|  - HOME_NET: 10.0.0.0/8  |    - Analyst annotations |
|  - Victim IPs: 214.16.69.74                          |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  Records by Type                                     |
|  ┌─────────────────┬───────┐                         |
|  │ suricata_alert   │   847 │  ← click opens list   |
|  │ zeek_conn        │  2341 │                        |
|  │ tshark_stream    │   160 │                        |
|  │ win_evt_security │  5420 │                        |
|  │ win_evt_powershell│  312 │                        |
|  │ win_evt_sysmon   │  1205 │                        |
|  │ volatility_pslist│    89 │                        |
|  └─────────────────┴───────┘                         |
|                                                      |
+------------------------------------------------------+
|                                                      |
|  Active Case          |    Plugin Status             |
|  - Tasks: 3/5 done    |    ✓ pcap (v0.1.0)          |
|  - Findings: 12       |    ✓ winevt (v0.1.0)        |
|  - Last activity: 2m  |    ✓ memory (v0.1.0)        |
|                       |    ✓ threat-hunter (v0.2.0) |
|                                                      |
+------------------------------------------------------+
```

### Navigation from Dashboard

- Click a record type → opens filtered record list
- Click a record type that has an OCSF view → option to open OCSF Analytics view
- OCSF Analytics view → column filters, sort, search, export
- Windows Event Logs are broken out by channel name (Security, PowerShell, Application, System, Sysmon)
- Case Notes → editable annotations area
- Active Case panel → links to tasks, findings, reports, worklog

All dashboard data comes from SQL aggregation queries — no LLM involvement.

---

## 6. Pre-computation & Query Learning

### Pre-computation

When the LLM gets tasked, before the RLM loop starts, the platform runs pre-coded queries and stashes results in the scratch database:

```
Task assigned
    ↓
Run plugin precompute functions
    ↓
Results → scratch_precomputed table
    ↓
LLM REPL has get_precomputed(name) function
    ↓
RLM loop starts
```

Each plugin declares precompute functions in its manifest. Examples for PCAP:

| Function | Output |
|----------|--------|
| `top_talkers` | Source/dest IP pairs by volume |
| `alert_severity_counts` | Alert counts by severity level |
| `protocol_distribution` | Protocol breakdown |
| `connection_timeline` | Connections bucketed by time |

The LLM can call `get_precomputed("top_talkers")` to get instant results instead of writing the query from scratch.

### Query Learning

The platform mines `worklog_step` records to identify frequently-used query patterns:

1. **Collect** — extract SQL/Python from worklog steps across completed tasks
2. **Normalize** — strip literal values, extract query structure
3. **Count** — track frequency of each normalized pattern
4. **Promote** — when a pattern exceeds a threshold (e.g., used in 5+ tasks), flag it for review
5. **Codify** — admin reviews flagged patterns and promotes them to pre-computed queries

This creates a feedback loop: LLM investigations → discovered patterns → pre-computed queries → faster future investigations with less LLM compute.

Query learning runs as a background job, not in real-time. The admin reviews candidates before promotion.

---

## 7. End-to-End Data Flow

```
Evidence Upload (PCAP, EVTX, Volatility output)
    ↓
Plugin ingest handler (deterministic parsing)
    ↓
Records table (raw JSONB + metadata)
    ↓
OCSF mapper (deterministic column extraction)
    ↓
OCSF views (flat columns for SQL analytics)
    ↓
Entity extraction (regex IOC patterns → entities table)
    ↓
Dashboard widgets populate (SQL aggregations)
    ↓
Analyst creates/assigns investigation task
    ↓
Pre-computation runs (plugin precompute functions)
    ↓
Results stashed in scratch_precomputed
    ↓
RLM loop starts (LLM writes Python in Docker REPL)
    ↓
LLM queries DB, calls get_precomputed(), get_docs()
    ↓
Each step → worklog_step record (code, output, timing)
    ↓
LLM produces findings with evidence record IDs
    ↓
Report generation (structured template + LLM prose)
    ↓
Query learning mines worklog (background)
```

Every step is auditable. Every finding traces back to executed code and evidence record IDs.

---

## 8. Project Structure & Migration Map

### Directory Structure

```
EvidenceLab/
├── docs/
│   └── plans/
├── src/
│   └── sphinx/
│       ├── core/
│       │   ├── __init__.py
│       │   ├── app.py              # FastAPI application
│       │   ├── auth.py             # JWT validation, RBAC middleware
│       │   ├── config.py           # Environment and settings
│       │   ├── db.py               # PostgreSQL connection management
│       │   ├── models.py           # SQLAlchemy / Pydantic models
│       │   ├── plugin_loader.py    # Plugin discovery and registration
│       │   ├── dashboard.py        # Dashboard data endpoints
│       │   ├── case_manager.py     # Case CRUD operations
│       │   ├── task_runner.py      # Task assignment and RLM loop trigger
│       │   ├── rlm_loop.py         # Step-bounded investigation loop
│       │   ├── planner.py          # Prompt assembly, history compaction
│       │   ├── sandbox.py          # Docker REPL sandbox
│       │   ├── precompute.py       # Pre-computation orchestrator
│       │   ├── query_learner.py    # Worklog pattern mining
│       │   ├── report.py           # Report generation
│       │   ├── entity_extractor.py # Regex-based IOC extraction
│       │   └── prompts/
│       │       ├── system.py       # Core platform prompts only
│       │       └── templates.py    # Report templates
│       └── plugins/
│           ├── sphinx_plugin_pcap/
│           │   ├── manifest.py
│           │   ├── ingest.py
│           │   ├── ocsf.py
│           │   ├── precompute.py
│           │   ├── widgets.py
│           │   ├── prompts.py
│           │   └── sql/
│           ├── sphinx_plugin_winevt/
│           │   ├── manifest.py
│           │   ├── ingest.py
│           │   ├── ocsf.py
│           │   ├── precompute.py
│           │   ├── widgets.py
│           │   ├── prompts.py
│           │   └── sql/
│           ├── sphinx_plugin_memory/
│           │   ├── manifest.py
│           │   ├── ingest.py
│           │   ├── ocsf.py
│           │   ├── precompute.py
│           │   ├── widgets.py
│           │   ├── prompts.py
│           │   └── sql/
│           └── sphinx_plugin_threat_hunter/
│               ├── manifest.py
│               ├── correlator.py
│               ├── mitre.py
│               ├── precompute.py
│               ├── widgets.py
│               ├── prompts.py
│               └── sql/
├── sql/
│   ├── 001_core_schema.sql
│   ├── 002_rbac.sql
│   ├── 003_worklog.sql
│   ├── 004_precomputed.sql
│   ├── 005_query_patterns.sql
│   └── 006_plugin_migrations.sql
├── docker/
│   ├── Dockerfile
│   ├── Dockerfile.repl
│   └── docker-compose.yml
├── tests/
├── pyproject.toml
├── .env.example
└── README.md
```

### Migration Map from ResilientCORE

| ResilientCORE | Sphinx | Notes |
|---------------|--------|-------|
| `src/rlm/rlm_loop.py` | `src/sphinx/core/rlm_loop.py` | Simplified, plugin-aware |
| `src/rlm/planner.py` | `src/sphinx/core/planner.py` | Core prompts only |
| `src/rlm/sandbox.py` | `src/sphinx/core/sandbox.py` | Same Docker REPL model |
| `src/rlm/tools.py` | Split into plugin ingest handlers | Per-plugin tool registration |
| `src/rlm/templates.py` | `src/sphinx/core/prompts/` + plugin `prompts.py` | Prompts travel with plugins |
| `src/rlm/report.py` | `src/sphinx/core/report.py` | Template-driven, minimal LLM |
| `src/rlm/sub_query.py` | `src/sphinx/core/planner.py` | Merged into planner |
| `src/analytics/` | Plugin `precompute.py` + `ocsf.py` | Per-plugin analytics |
| `sql/001-011` | `sql/001-006` + plugin `sql/` | Core schema + plugin migrations |
| Monolithic ingest | Plugin `ingest.py` files | Each plugin owns its parsers |
| Global system prompt | Core prompt + plugin prompts | Prompts registered at plugin load |

---

## Appendix: Design Decisions

1. **Why plugins over monolith?** — Keeps core small, allows independent plugin development/deployment, evidence types vary wildly between engagements.

2. **Why JWT at API layer?** — Stateless, case-scoped claims, works with both human users and LLM agents, standard tooling.

3. **Why pre-computation?** — Reduces LLM token spend, provides instant baseline analytics, makes small models viable for investigation.

4. **Why query learning?** — Creates a virtuous cycle where LLM usage decreases over time as common patterns get codified.

5. **Why two LLM modes?** — Single-case investigation is the common path; cross-case correlation is a specialized need with different access patterns and security implications.

6. **Why prompts with plugins?** — Evidence-type-specific instructions (field names, query patterns, detection logic) belong with the code that handles that evidence type. Core shouldn't know about Suricata field names.