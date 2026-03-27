# EvidenceLab User Manual

## Introduction

EvidenceLab is a plugin-based incident response investigation platform that combines automated evidence parsing with LLM-driven analysis. It ingests network captures (PCAPs), Windows Event Logs, and memory forensics output, stores everything in a structured database, and provides a web-based dashboard for security analysts to investigate incidents with AI assistance.

This manual covers every page and feature in the platform, organized in the same order they appear in the sidebar menu.

---

## Getting Started

### Logging In

When you first open EvidenceLab, you will see the **Sign In** page.

1. Enter your **Username** and **Password**.
2. Click **Sign In**.

Your administrator will have created your account and provided your credentials. If you cannot log in, contact your administrator to verify your account is active and your credentials are correct.

Once signed in, you will be taken to the **Dashboard**. Your username and role are displayed at the bottom of the sidebar on every page.

### Logging Out

Click **Logout** from the sidebar footer or navigate to `/ui/logout`. This clears your session and returns you to the Sign In page.

### Roles and Permissions

EvidenceLab has four roles, each with increasing levels of access:

| Role | What You Can Do |
|------|-----------------|
| **LLM Agent** | Lowest privilege. Service account for AI investigation tasks. Receives a short-lived JWT scoped to the task's case(s). Connects to the database via a restricted role with row-level security. Cannot access admin pages. |
| **Analyst** | Create and investigate cases, run tasks, ingest evidence, manage findings and rules. Can only access cases assigned to you. |
| **Case Manager** | Everything an Analyst can do, plus access to all cases (not just assigned ones). |
| **Admin** | Full access. Everything above, plus user management, data management, and query learning administration. |

### Understanding the Sidebar

The sidebar is your main navigation tool. It has three sections:

1. **Global pages** (always visible): Dashboard, Cases
2. **Case pages** (visible after selecting a case): Records, Tasks, Ingest, Entities, Findings, Detection Rules, Analytics, Notes, Report
3. **Admin pages** (visible to admins only): Admin: Users, Admin: Data, Admin: Queries

### The Help Button

Most pages have a **?** button in the top-right corner. Click it to open a help overlay with page-specific guidance. Click the **X** or click outside the overlay to close it.

---

## Dashboard

**Sidebar:** Dashboard | **URL:** `/ui/`

The Dashboard is your home page. It shows an overview of your current case and provides controls for switching between investigation modes.

### Investigation Modes

EvidenceLab supports two investigation modes:

#### Investigator Mode (Default)

In Investigator mode, you work on **one case at a time**. This is the standard mode for most investigations.

- Select a case from the **Select Case** dropdown at the top of the dashboard.
- The dashboard and all case-specific sidebar pages will show data from this case.

#### Correlator Mode

Correlator mode allows you to investigate **across multiple cases simultaneously**. This is useful when you suspect related incidents (e.g., a coordinated attack campaign targeting multiple systems).

To use Correlator mode:

1. Click the **Correlator** button at the top of the Dashboard.
2. Select two or more **source cases** using the checkboxes.
3. Select or create a **correlation case** — this is where cross-case findings will be stored.
4. Click **Apply Configuration**.

When in Correlator mode, the AI can query evidence from all source cases and identify shared indicators of compromise (IOCs), overlapping MITRE ATT&CK techniques, and coordinated activity timelines.

A blue **correlator** badge appears next to your role in the sidebar footer when this mode is active.

### Case Settings

When a case is selected, the Dashboard shows a **Case Settings** panel where you can configure:

- **HOME_NET** — CIDR ranges that define your internal network (e.g., `192.168.1.0/24, 10.0.0.0/8`). Used by Suricata for alert classification. Separate multiple ranges with commas.
- **Victim IPs** — Specific IP addresses of compromised or targeted hosts (e.g., `192.168.1.100, 192.168.1.105`). Helps the AI focus its investigation.
- **Case Description** — Free-text description of the incident for context.

Click **Save Settings** after making changes.

### Dashboard Panels

The Dashboard displays several information panels when a case is selected:

- **Summary Cards** — Total record count, task completion status, findings count, and entity count.
- **Records by Type** — Table showing how many records exist for each evidence type (e.g., `suricata_alert`, `zeek_conn`, `win_evt_security`). Click **View** to jump to filtered records.
- **Background Jobs** — Status of ongoing ingest jobs with progress bars and record counts.
- **Loaded Plugins** — Which evidence-type plugins are active and their versions.

---

## Cases

**Sidebar:** Cases | **URL:** `/ui/cases`

The Cases page lists all investigation cases you have access to.

### Viewing Cases

Each case shows its **name**, **status** (open or closed), and **creation date**. Click **Open** or click the case name to select it and go to its Dashboard.

### Creating a New Case

1. Click **+ New Case**.
2. Enter a **Case Name** (required) — for example, "2024-03 Server Compromise Investigation".
3. Optionally enter a **Description** for context.
4. Click **Create Case**.

The new case is created and you are redirected to its Dashboard. From there, you can configure case settings and begin ingesting evidence.

---

## Records

**Sidebar:** Records | **URL:** `/ui/cases/{case_id}/records`

The Records page shows all evidence records stored in the current case. A "record" is a single parsed event — a Suricata alert, a Zeek connection log, a Windows security event, a Volatility process entry, etc.

### Where To Hunt For Rule Candidates

The **Analytics** page is the main hunting workspace for detection engineering. Use it to identify suspicious patterns, narrow to a likely event family, and then pivot into **Records** for close inspection.

- For **Sigma** rules, start with Windows event records (`win_evt_security`, `win_evt_sysmon`, `win_evt_powershell`, etc.).
- The **Analytics** page includes clickable record-type cards for quick hunting pivots, plus **Windows ATT&CK Starter Filters** with cumulative dropdowns for **Tactic**, **Technique**, and **EventID starter**.
- Those dropdowns are populated from the local Windows ATT&CK mapping dataset bundled with the platform.
- Once you identify a promising event family, open the matching record in **Records**.
- The record detail page explains the event, shows important fields, and gives case-level context so you can decide whether a detection is justified.
- If the event still looks rule-worthy after inspection, use **Build Sigma Rule From Event** or **Build Suricata Rule From Record** from the detail page.

### Browsing Records

Records are displayed in a paginated table showing:

- **ID** — Unique identifier
- **Type** — The record type (e.g., `suricata_alert`, `zeek_conn`, `win_evt_security`)
- **Timestamp** — When the event occurred
- **Channel / Event** — For Windows logs, the channel name and EventID
- **Summary Hint** — A quick preview of a useful field such as username, image path, command line, or other high-signal content
- **Detail** — Link to view the full record

Use the **Previous** and **Next** buttons at the bottom to navigate through pages.

### Filtering and Hunting

Use the filters at the top of the page to narrow the dataset before opening a record:

- **Type** — filter to a specific evidence source
- **Windows Channel** — focus on Security, Sysmon, PowerShell, Application, or System
- **EventID** — search for a specific Windows event ID such as `4624`, `4625`, `4688`, or `4104`
- **Search Raw Data** — free-text search across the record JSON for usernames, process names, command lines, IP addresses, and other indicators

This page is the detailed evidence browser you use after hunting in Analytics. It is where you inspect a specific event closely enough to decide whether it should become a detection candidate.

Common record types include:

| Type | Source | Description |
|------|--------|-------------|
| `suricata_alert` | PCAP (Suricata) | IDS alert triggered by a detection rule |
| `suricata_http` | PCAP (Suricata) | HTTP transaction metadata |
| `suricata_dns` | PCAP (Suricata) | DNS query and response |
| `suricata_tls` | PCAP (Suricata) | TLS/SSL handshake metadata |
| `suricata_flow` | PCAP (Suricata) | Network flow summary |
| `zeek_conn` | PCAP (Zeek) | Connection log (src/dst, bytes, duration) |
| `zeek_dns` | PCAP (Zeek) | DNS query details |
| `zeek_http` | PCAP (Zeek) | HTTP request/response details |
| `zeek_ssl` | PCAP (Zeek) | SSL/TLS certificate info |
| `zeek_files` | PCAP (Zeek) | Files transferred over network |
| `tshark_stream` | PCAP (tshark) | Reassembled TCP stream payloads |
| `win_evt_security` | Windows Event Log | Security events (logons, process creation) |
| `win_evt_powershell` | Windows Event Log | PowerShell script block logging |
| `win_evt_sysmon` | Windows Event Log | Sysmon process/network/file events |
| `win_evt_taskscheduler` | Windows Event Log | Task Scheduler Operational events |
| `win_evt_application` | Windows Event Log | Application log events |
| `win_evt_system` | Windows Event Log | System log events |
| `vol_pslist` | Memory (Volatility) | Running processes |
| `vol_netscan` | Memory (Volatility) | Network connections in memory |
| `vol_cmdline` | Memory (Volatility) | Command-line arguments per process |
| `vol_dlllist` | Memory (Volatility) | Loaded DLLs per process |
| `vol_handles` | Memory (Volatility) | Open handles (files, registry, mutexes) |
| `vol_malfind` | Memory (Volatility) | Suspicious memory regions (injected code) |

### Viewing Record Details

Click **Detail** on any record to view its full contents:

- **Record metadata** — ID, type, and timestamp in summary cards.
- **Detection Context** — A merged table showing signature priority, type, field, value, context metric, and reason for candidate rule anchors.
- **Extracted Entities** — Any IOCs (IP addresses, domains, hashes, emails, URLs, usernames) automatically extracted from this record.
- Entity extraction is heuristic. The platform filters common false positives such as browser version strings and time-only values where possible.
- **Raw Data** — The complete JSON data for the record, displayed in a formatted viewer as literal escaped text.

If the record is a Windows event, the detail page includes a **Build Sigma Rule From Event** button that pivots directly into the guided Sigma authoring flow.
That button appears alongside summary context so the analyst can make the decision with more confidence.

The Sigma builder now follows the same interactive pattern as the Suricata builder:

- **Step 1: Review The Event** keeps the selected Windows event, EventData fields, and raw JSON visible.
- **Step 2: Case Support Context** shows channel counts, top EventIDs, and observed EventData keys.
- **Step 3: Select Stable Sigma Atoms** turns `EventID`, `logsource.service`, and `EventData.*` values into selectable cards.
- **Override controls** inside each Sigma card let the analyst change the Sigma field name, match operator, and value without editing raw YAML first.
- **Step 4: Live Rule Preview** renders the selected atoms into Sigma YAML automatically.
- After opening the manual Sigma draft, the analyst can use **Test Against Current Case Events** to compile and run the draft against the current case before saving it.

---

## Tasks

**Sidebar:** Tasks | **URL:** `/ui/cases/{case_id}/tasks`

Tasks are AI-powered investigation queries. When you create a task, the LLM receives your question, analyzes the evidence in the case, and produces findings.

### How Tasks Work

1. You write an investigation question (e.g., "Identify all indicators of lateral movement in the network traffic").
2. The system pre-computes analytics from your evidence (top talkers, alert summaries, process trees, etc.).
3. The LLM enters a **Reasoning Loop** where it writes and executes Python code in a sandboxed environment to query the database, analyze patterns, and build conclusions.
4. Each step is logged in a **worklog** for full transparency.
5. When the LLM reaches a conclusion, it produces a **finding** with evidence citations and MITRE ATT&CK technique mappings.

### Creating a Task

1. Click **+ New Task**.
2. Enter your **Investigation Question** — be specific about what you want investigated. Examples:
   - "Analyze the Suricata alerts and identify the attack chain used against the victim hosts."
   - "Examine the PowerShell script blocks for signs of obfuscation or encoded commands."
   - "Correlate the process creation events with network connections to identify C2 communication."
3. Set the **Max Steps** (default: 15, range: 1–50). More steps allow deeper investigation but take longer.
4. Click **Create & Run**.

### Task Statuses

| Status | Meaning |
|--------|---------|
| **Pending** | Task created but not yet started |
| **Running** | LLM is actively investigating (steps are being added in real-time) |
| **Done** | Investigation complete — a finding has been produced |
| **Failed** | Something went wrong during investigation |
| **Cancelled** | Task was stopped before completion |

### Viewing Task Details

Click **View** on any task to see its detail page. For running tasks, the page streams updates in real-time:

- **Task Info** — Title, status, description, creation time, step count.
- **Live Indicator** — A pulsing badge appears while the task is actively running.
- **Worklog Steps** — Each step shows:
  - **Intent** — What the LLM planned to do in this step.
  - **Code** — The Python code the LLM wrote and executed.
  - **Output** — The result of executing the code (stdout).
  - **Errors** — Any errors that occurred (stderr or exceptions).
  - **Elapsed Time** — How long the step took to execute.
- **Finding** — When the task completes, the final finding is displayed with the LLM's conclusions, evidence citations, and MITRE ATT&CK mappings.

---

## Ingest

**Sidebar:** Ingest | **URL:** `/ui/cases/{case_id}/ingest`

The Ingest page is where you upload evidence files into a case.

### Supported Evidence Formats

#### PCAP Files (Network Captures)

File types: `.pcap`, `.pcapng`, `.cap`

When you upload a PCAP file, three network analysis tools process it automatically:

1. **Suricata** — Runs IDS rules against the traffic, producing alerts, HTTP/DNS/TLS/flow logs.
2. **Zeek** — Extracts connection logs, protocol-specific logs (DNS, HTTP, SSL, files, etc.).
3. **tshark** — Reassembles TCP streams for payload inspection.

PCAP processing runs as a **background job**. You can monitor its progress on the Dashboard.

#### JSON/JSONL Files

File types: `.json`, `.jsonl`

For pre-processed evidence that has already been exported from other tools:

1. Select the **Record Type** from the dropdown (e.g., `win_evt_security`, `vol_pslist`).
2. Upload the JSON or JSONL file.
3. Records are parsed and stored immediately.

This is used for:
- **Windows Event Logs** — Export from EVTX files using standard tools, then upload as JSON.
- **Volatility 3 Output** — Export process lists, network scans, DLL lists, etc. as JSON.

#### EVTX Files (Native Windows Event Logs)

File type: `.evtx`

When you upload a native EVTX file:

1. EvidenceLab parses the Windows event XML directly.
2. It auto-detects the event channel and routes supported events to the appropriate `win_evt_*` record type.
3. It preserves the original event time and stores it in the record timestamp field used throughout the UI and analytics.

This is the simplest way to ingest Windows event logs because it keeps the original event timing intact for Records, Analytics, and correlations. Supported EVTX channel routing currently includes **Security**, **PowerShell**, **Sysmon**, **Task Scheduler Operational**, **Application**, and **System**.

### How to Ingest Evidence

1. Select the **Ingest Mode** — "JSON", "Windows Event Log (EVTX)", or "PCAP".
2. For JSON mode, select the appropriate **Record Type**.
3. Click **Choose File** and select your evidence file.
4. Click **Upload & Ingest**.

For PCAP files, processing happens in the background. The Ingest page and Dashboard both show the current case's recent background jobs and live progress for any running ingest. When EvidenceLab can determine the total expected derived records, the progress display also shows `processed / total` counts alongside the progress bar.

PCAP conversion runs in the isolated REPL container, but the derived Suricata, Zeek, and tshark records are written back through an internal ingest connection. This keeps the normal interactive REPL role restricted while still allowing background ingest to populate case records.

### Available Handlers

The Ingest page now keeps **Available Handlers** collapsed by default as an advanced troubleshooting section.

- Expand it if you want to see the registered ingest handler names and normalized record types.
- This is mostly useful for troubleshooting or plugin/operator visibility.
- Most analysts can ignore it and focus on ingest mode, background jobs, and current case record counts.

---

## Entities

**Sidebar:** Entities | **URL:** `/ui/cases/{case_id}/entities`

Entities are indicators of compromise (IOCs) automatically extracted from your evidence records. The platform uses pattern matching to identify IP addresses, domains, email addresses, URLs, file hashes, and usernames.

Entity extraction is heuristic rather than perfect parsing. EvidenceLab applies false-positive filtering for common mistakes such as browser version strings that resemble IPv4 addresses and bare time values that resemble IPv6 addresses.

### Entity Types

| Type | Description | Example |
|------|-------------|---------|
| `ip` | IPv4 or IPv6 address | `192.168.1.100`, `2001:db8::1` |
| `domain` | Domain name | `evil-server.com` |
| `email` | Email address | `attacker@malware.org` |
| `url` | Full URL | `http://evil-server.com/payload.exe` |
| `hash_md5` | MD5 file hash (32 hex chars) | `d41d8cd98f00b204e9800998ecf8427e` |
| `hash_sha1` | SHA-1 file hash (40 hex chars) | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `hash_sha256` | SHA-256 file hash (64 hex chars) | `e3b0c44298fc1c149afbf4c8996fb924...` |
| `username` | Windows username (DOMAIN\user) | `CORP\jsmith` |

### Searching Entities

1. Type a value (or partial value) in the **Search** box.
2. Optionally filter by **Entity Type** using the dropdown.
3. Click **Search**.

Results show each matching entity with its type, value, and how many records reference it.

### Entity Type Summary

When no search is active, the page shows **summary cards** for each entity type with the count of unique values and total references. Click a card to filter to that type.

### Pivot Analysis

Click **Pivot** on any entity to open the **Entity Pivot** view. This shows:

- **Total References** — How many records contain this entity.
- **Record Types** — Which evidence sources reference this entity (e.g., it appears in both Suricata alerts and Zeek connection logs).
- **All Records** — A table of every record containing this entity, with links to record details.
- **Co-occurring Entities** — Other entities that appear in the same records. This is powerful for discovering relationships — for example, finding that a suspicious IP always appears alongside a specific domain or hash.

You can click **Pivot** on any co-occurring entity to chain pivots and follow the trail.

---

## Findings

**Sidebar:** Findings | **URL:** `/ui/cases/{case_id}/findings`

Findings are the conclusions produced by AI investigation tasks. Each finding represents a piece of the investigation — an attack technique identified, a suspicious pattern discovered, or a correlation established.

### Viewing Findings

Each finding card shows:

- **Title** — A brief description of what was found.
- **Summary** — The detailed analysis text.
- **Evidence IDs** — The specific record IDs that support this finding (citations).
- **MITRE ATT&CK** — Relevant technique IDs (e.g., T1059.001 for PowerShell execution).
- **Severity** — How critical the finding is: Critical, High, Medium, Low, or Info.

### Generating Detection Rules from Findings

You can turn findings into automated detection rules:

1. Select one or more findings using the **checkboxes** on the right side of each card.
2. The selection counter at the top updates to show how many findings are selected.
3. Click **Generate Detection Rules**.
4. The AI will analyze the selected findings and their supporting evidence to create Sigma (for log-based detection) or Suricata (for network-based detection) rules.
5. Generated rules appear on the **Detection Rules** page with a "pending review" status.

Tips for generating good rules:
- Select findings that describe **behavioral patterns** (not just single IOCs).
- Findings with strong **evidence citations** produce better rules.
- Findings with **MITRE ATT&CK mappings** help the AI understand the attack context.

### Deleting Findings

You can delete findings you created by clicking the **trashcan icon** to the left of the finding card.

- **Analysts, Case Managers**: Can delete findings generated by tasks they created.
- **Admins**: Can delete any finding.
- **LLM Agents**: Cannot delete findings.

Deletions are permanent and cannot be undone. A confirmation dialog will appear before the finding is removed.

---

## Detection Rules

**Sidebar:** Detection Rules | **URL:** `/ui/cases/{case_id}/detection-rules`

Detection Rules are Suricata or Sigma rules that can be deployed to detect similar attacks in the future.

### Rule Types

| Type | Format | Detects |
|------|--------|---------|
| **Suricata** | Suricata rule syntax | Network-based threats (malicious traffic, C2, exploits) |
| **Sigma** | YAML | Log-based threats (suspicious process creation, PowerShell abuse, logon anomalies) |

### Rule Lifecycle

Rules progress through these statuses:

1. **Pending Review** — Newly generated or imported, needs human review.
2. **Approved** — Reviewed and approved by an analyst.
3. **Deployed** — Active and running against new evidence.
4. **Rejected** — Reviewed and rejected (false positive, too broad, etc.).

### Viewing Rules

The rules list can be filtered by status using the tabs: **All**, **Pending Review**, **Approved**, **Deployed**.

Each rule shows its title, type, status, origin case, MITRE IDs, and creation date.

### Creating a Rule Manually

1. Click **+ New Rule**.
2. Enter a **Title** for the rule.
3. Select the **Rule Type** (Suricata or Sigma).
4. Write the **Rule Content** in the appropriate syntax.
5. Optionally add a **Description**.
6. Optionally click **Test Against Latest Case PCAP** to run the draft rule offline against the most recent uploaded PCAP for the case and review the match summary. EvidenceLab now retains uploaded PCAPs so analysts can test rules after ingest. Multiline Suricata drafts entered in the editor are normalized automatically before testing and deployment. If the main rule returns zero matches, the page also shows automatic probe variants that help diagnose whether the miss is caused by direction, stream-only matching, or the selected content pattern.
7. Click **Create Rule** (saves as pending review) or **Create & Deploy** (immediately active).

### Guided Deterministic Authoring

EvidenceLab also supports a guided, no-AI authoring workflow:

1. Hunt in **Analytics** and inspect a candidate event on the **Record Detail** page.
2. Review the **Detection Context** table, which ranks fields with `SigPriority` values of `High`, `Medium`, or `Low`.
3. Use the `Context Metric` column to see how often that same type, field, and value appears in the current case.
4. Open the Sigma or Suricata builder from the record detail page.
5. Review the deterministic field recommendations again inside the builder.
6. Open the prefilled draft and refine it before saving or deploying.

When using the Suricata builder, the page keeps the full source record JSON visible and adds a guided no-AI workflow: review the normalized flow, choose a detection strategy, choose a content match style, select High/Medium/Low candidate atoms, and watch the Suricata rule preview update automatically. Payload previews are shown in an escaped JSON-style string format, and JSON panes are rendered as escaped literal text so evidence content cannot be interpreted as page markup. Behavior and service-focused previews ignore high ephemeral ports by default, because those ports are usually too brittle for a durable rule. Candidate content atoms also show frame-level provenance so the analyst can tell whether a string was seen wholly inside one payload-bearing frame or only after stream reassembly. When a selected anchor is tied to specific frames, the preview now prefers the observed `to_server` / `to_client` direction from that frame provenance instead of relying only on the stream-wide port summary. Because tshark stream summaries only capture the first payload-bearing packet in a stream, new `tshark_stream` records now also store canonical client/server roles inferred from the service port so the builder can show both the raw stream orientation and the more stable client/server interpretation. When EvidenceLab can tie a content anchor to specific payload-bearing frames, the displayed source/destination endpoint anchors follow that anchor-frame context rather than the coarse stream summary, and the explicit `flow:to_server` / `flow:to_client` card uses that same active anchor context. Endpoint cards for IPs and ports are now overridable, so the analyst can swap `src`/`dst` and choose from the observed endpoint values directly inside the cards when the initial orientation needs correction. Flow cards are now overridable too, with dropdowns for common Suricata `flow` keywords and separate stream-scope control, so the analyst can choose the exact flow constraint to carry into the draft. Explicit flow selections now override the builder's inferred direction, and `only_stream` / `no_stream` are no longer silently auto-added. In the recommended match style, reassembly-dependent strings are normally rendered as resilient token-sequence PCRE patterns, but if the builder can prove that a strong sub-token was seen wholly inside one payload-bearing frame, it prefers that packet-scoped literal instead and reuses that same fallback anchor context for the cards and the live preview. Single-packet literal anchors also avoid auto-adding `flow` keywords when those constraints would likely over-restrict the rule, and the default checkbox selection now starts conservatively instead of preselecting weak port or flow anchors. When an analyst explicitly checks an IP, port, or flow anchor, that choice now carries into the live draft instead of being silently overridden by inferred defaults. If no content anchor and no port anchor are selected, the preview now leaves the header at `any any -> any any` instead of silently backfilling a service port from stream summary data. After opening the draft in the manual editor, the analyst can test the rule against the latest uploaded case PCAP before saving it. If the main rule returns zero matches, the form now shows automatic probe diagnostics, including source-side and destination-side service-port checks, paired flow-keyword probes, and a broad any-any literal-content probe, to help distinguish a builder issue from a deeper Suricata test-path issue.

This workflow is designed to help junior analysts build detections without requiring AI assistance.

### Reviewing a Rule

Click on a rule title or the **Review** button to open the review page:

- **Rule Content** — View and edit the rule text. Click **Save Changes** after editing.
- **Source Finding** — If the rule was generated from a finding, the original finding is shown for context.
- **Review Actions:**
  - **Approve** — Mark the rule as reviewed and acceptable.
  - **Reject** — Mark the rule as rejected.
  - **Deploy** — Make the rule active. For Suricata rules, this adds the rule to the active rules file. For Sigma rules, this compiles the rule to SQL and runs it against existing evidence.
  - **Re-generate** — Ask the AI to regenerate the rule from the original finding.
  - **Export** — Download the rule as a file (`.rules` for Suricata, `.yml` for Sigma).

### Deploying Rules

- **Suricata rules**: When deployed, the rule is written to the active Suricata rules directory. New PCAP ingests will be checked against this rule.
- **Sigma rules**: When deployed, the YAML is compiled to a SQL query and executed against existing Windows Event Log records. Matches appear as new records.

---

## Analytics

**Sidebar:** Analytics | **URL:** `/ui/cases/{case_id}/analytics`

The Analytics page provides interactive data exploration tools for querying and visualizing your evidence without writing code.

### Enabling Analytics

Analytics must be enabled for each case. Toggle the **Enable Analytics** checkbox at the top of the page.

### Using Analytics

1. **Start with a Hunt Strategy** — Either click a Windows ATT&CK starter filter or click a record-type card from the summary at the top.
2. **Choose a Mode** — Select one of the analysis modes:

### Windows ATT&CK Starter Filters

For Windows event hunting, the page includes a **Windows ATT&CK Starter Filters** panel.

- Start by choosing a **Tactic**.
- Then choose an applicable **Technique** from that tactic.
- Finally choose an **EventID starter** that matches the Windows evidence source you want to inspect.
- The selector is populated from the local Windows ATT&CK mapping dataset bundled with the platform.
- Applying the selection loads a specific Windows record type and starter EventID or channel filters into the Analytics query workflow.
- You can also click a record-type card near the top of the page to jump straight into that evidence source without using the ATT&CK selector.
- Use these presets as a fast way to begin hunting for behaviors such as:
  - cleared event logs
  - suspicious service installation
  - scheduled task creation
  - PowerShell abuse
  - Kerberoasting
- These are starter filters, not finished detections. You should still inspect the resulting records before deciding to create a Sigma rule.

#### Browse Mode

Simple table view of records with interactive filtering. This is often the fastest way to narrow to a candidate event before opening it in the Records page for detailed inspection.

- Click any cell value to add it as a filter.
- Click column headers to sort.
- Use the filter panel to add custom filters.

#### Value Counts Mode

Count unique values in a column. Useful for finding the most common IPs, ports, event types, etc.

1. Select the **Column** to count.
2. Click **Query**.
3. Results show each unique value and its count, sorted by frequency.

#### Relationships Mode

Discover relationships between two columns.

1. Select **Column A** and **Column B** (e.g., `src_ip` and `dest_ip`).
2. Click **Query**.
3. Results show every combination of values and how often they occur together.

#### Time Series Mode

View event counts over time.

1. Select the **Interval** (minute, hour, day, or week).
2. Optionally select a **Group By** column to break down the timeline.
3. Click **Query**.
4. Results show event counts per time bucket.

#### Top-N Mode

Find the top values by an aggregation.

1. Select the **Group By** column (the field to rank).
2. Optionally select a **Metric** column and **Aggregation** function (COUNT, SUM, AVG, MIN, MAX, COUNT DISTINCT).
3. Click **Query**.
4. Results show the top values ranked by the selected metric.

#### Correlate Mode

Find temporal correlations between different record types.

1. Select **Type A** and **Type B** (e.g., `suricata_alert` and `zeek_conn`).
2. Set the **Time Window** (how close in time events must be to correlate).
3. Optionally select a **Shared Entity** type (e.g., `ip`) to require matching entities.
4. Click **Query**.
5. Results show correlated event pairs from different evidence sources.

### Hunt Then Inspect

The intended workflow for building a rule is:

1. Hunt in **Analytics** using ATT&CK starter filters, manual filters, or aggregations.
2. Identify a suspicious event family or outlier.
3. Open a specific record from the results table.
4. Inspect that event on the **Record Detail** page.
5. Only then pivot into Sigma or Suricata authoring.

### Filtering

The filter panel (available in all modes except Correlate) lets you add conditions:

1. Click **+ Add Filter**.
2. Select a **Column**, **Operator** (equals, not equals, contains, greater than, less than), and **Value**.
3. Add multiple filters to narrow your query.
4. Click **Query** to apply.
5. Click **Clear** to remove all filters.

You can also set a **Limit** (default 200, max 5000) and **Sort** direction.

---

## Notes

**Sidebar:** Notes | **URL:** `/ui/cases/{case_id}/notes`

Notes are free-text annotations attached to a case. Use them to record analyst observations, hypotheses, handoff notes, or any information that doesn't fit into the structured investigation workflow.

### Adding a Note

1. Type your note in the text area.
2. Click **Save Note**.

Notes are timestamped and attributed to the logged-in user.

### Deleting a Note

Click the **Delete** button on any note. You will be asked to confirm before deletion. This action cannot be undone.

---

## Report

**Sidebar:** Report | **URL:** `/ui/cases/{case_id}/report`

The Report page generates a structured investigation report from all the data in the current case.

### Report Contents

- **Executive Summary** — An AI-generated overview of the investigation (if findings exist) or a summary of evidence counts.
- **Case Information** — Case name, status, and generation timestamp.
- **Evidence Summary** — Table of record types and counts.
- **Tasks** — List of all investigation tasks and their statuses.
- **Findings** — All findings with severity, descriptions, evidence citations, and MITRE ATT&CK mappings.
- **Indicators of Compromise** — Table of all extracted IOCs with types, values, and reference counts.

### Downloading the Report

Click **Download JSON** to save the full report as a JSON file. This can be imported into other tools or used for archival purposes.

---

## Admin: Users

**Sidebar:** Admin: Users | **URL:** `/ui/admin/users` | **Requires:** Admin role

The User Management page allows administrators to create and manage user accounts.

### Creating a User

1. Enter a **Username** (1–64 characters).
2. Enter a **Password** (minimum 8 characters).
3. Select a **Role** (Analyst, Case Manager, Admin, or LLM Agent).
4. Click **Create**.

### Managing Users

The users table shows all accounts with their username, role, status (active/inactive), creation date, and number of assigned cases.

- **Manage** — Click to open the user detail page (see below).
- **Deactivate/Activate** — Toggle whether a user can log in. Admin accounts cannot be deactivated from this button.

### User Detail Page

**URL:** `/ui/admin/users/{user_id}`

From the user detail page, you can:

- **Change Role** — Select a new role and click **Update**.
- **Reset Password** — Enter a new password (minimum 8 characters) and click **Reset**.
- **Assign Cases** — For Analyst and LLM Agent roles, assign specific cases using the dropdown and **Assign** button. Only assigned cases are visible to these roles.
- **Remove Case Assignments** — Click **Remove** next to any assigned case.

Note: Admin and Case Manager roles automatically have access to all cases, so the case assignment section is not shown for these roles.

### LLM Agent Service Account

An `llm_agent` service account is automatically created when the platform starts for the first time. This account is used internally by the investigation system:

- When an analyst runs a task, the system mints a **short-lived JWT** (30-minute expiry) for the `llm_agent`, scoped to the case(s) being investigated.
- In **Investigator mode**, the JWT is scoped to the single active case.
- In **Correlator mode**, the JWT is scoped to all selected source cases.
- The REPL container connects to the database as `sphinx_repl`, a restricted PostgreSQL role with SELECT-only access to evidence tables and row-level security (RLS) enforcing case boundaries.
- The `llm_agent` account cannot be used for interactive login — it has a random password that is never exposed.

You do not need to manage this account manually. It appears in the users list for visibility.

---

## Admin: Data

**Sidebar:** Admin: Data | **URL:** `/ui/admin/data` | **Requires:** Admin role

The Data Management page provides tools for permanently deleting evidence, cases, tasks, and detection rules. All deletions are irreversible.

### Delete Records by Ingest Job

Remove all evidence records created by a specific PCAP or file ingest job. Useful when an ingest produced bad data and needs to be re-run.

- The table shows recent ingest jobs with their type, input file name, status, and linked record count.
- Click **Delete Records** to remove all records from that job. The job record itself is kept (marked as "deleted") for audit purposes.
- Jobs without linked records (ingested before job tracking was added) show "no linked records" instead of a delete button.

### Delete Case Evidence

Remove all evidence from a case — records, entities, findings, tasks, worklog, and jobs — while keeping the case itself. Use this to reset a case for re-investigation.

- Only cases with records show the **Purge Evidence** button.

### Delete Entire Case

Permanently delete a case and everything tied to it: evidence, tasks, findings, notes, user assignments, and the case record itself.

- Every case has a **Delete Case** button regardless of whether it contains records.

### Delete Tasks

Delete individual investigation tasks and their worklog steps.

- The table shows all tasks across all cases with their ID, case name, title, status, and creation date.
- Running tasks cannot be deleted — they show a "running" badge instead of a delete button. Wait for the task to complete or cancel it first.
- Click **Delete** to remove a task and all its associated worklog steps.

### Detection Rules

Manage all detection rules across the platform.

- **Import Rules** — Upload a Suricata (`.rules`) or Sigma (`.yml`, `.yaml`) file to bulk-import rules into the database.
- **Edit** — Click to open the rule editor where you can modify the title, description, and rule content.
- **Deploy/Re-deploy** — Activate a rule from the admin interface.
- **Delete** — Remove a rule. If the rule was deployed, it is also removed from the active Suricata rules file.

### Important Notes

- Detection rules generated from a case's findings are **not deleted** when you delete the case — they are independent global assets.
- Only jobs with linked records show the "Delete Records" button.

---

## Admin: Queries

**Sidebar:** Admin: Queries | **URL:** `/ui/admin/query-learning` | **Requires:** Admin role

The Query Learning page helps optimize the platform by analyzing patterns in how the AI queries the database.

### How It Works

1. The AI writes SQL queries during investigation tasks, and these are logged in the worklog.
2. Click **Mine Worklog** to analyze all logged queries and identify recurring patterns.
3. Patterns are displayed with their **frequency** (how often the query appears) and **status**.

### Pattern Statuses

| Status | Meaning |
|--------|---------|
| **New** | Recently discovered pattern, not yet reviewed |
| **Promoted** | Linked to a precompute function — the query result will be pre-calculated before future investigations |
| **Dismissed** | Reviewed and determined to be unimportant |

### Managing Patterns

- **Promote** — Enter the name of a precompute function and click Promote. The system will run this computation before future tasks, so the AI can access the results instantly instead of re-running the query.
- **Dismiss** — Mark a pattern as unimportant. It won't be shown in the default view.
- **Restore** — Un-dismiss a previously dismissed pattern.

### Filtering

Use the tabs to filter by status: **All**, **Candidates** (new patterns), **Promoted**, **Dismissed**.

---

## Investigation Workflow Guide

Here is a typical end-to-end investigation workflow:

### Step 1: Create a Case

Go to **Cases** → **+ New Case**. Give it a descriptive name and optional description.

### Step 2: Configure Case Settings

On the **Dashboard**, set:
- **HOME_NET** to your internal network ranges.
- **Victim IPs** to the hosts under investigation.
- **Description** with incident context.

### Step 3: Ingest Evidence

Go to **Ingest** and upload your evidence files:
- Upload PCAPs for network traffic analysis.
- Upload JSON exports of Windows Event Logs.
- Upload Volatility 3 JSON output for memory forensics.

### Step 4: Review Ingested Data

- Check the **Dashboard** for record counts and job status.
- Browse **Records** to verify data was ingested correctly.
- Check **Entities** to see what IOCs were automatically extracted.

### Step 5: Run Investigation Tasks

Go to **Tasks** → **+ New Task**. Write specific investigation questions:
- Start broad: "Provide an overview of the network activity and identify any suspicious patterns."
- Then go deep: "Investigate the Suricata alerts related to IP 192.168.1.100 and determine the attack chain."
- Correlate sources: "Cross-reference the PowerShell script blocks with network connections to identify data exfiltration."

### Step 6: Review Findings

Go to **Findings** to review what the AI discovered. Each finding includes:
- A narrative summary of the analysis.
- Specific evidence record IDs as citations.
- MITRE ATT&CK technique mappings.
- Severity ratings.

### Step 7: Generate Detection Rules

On the **Findings** page, select relevant findings and click **Generate Detection Rules**. Review the generated rules on the **Detection Rules** page.

### Step 8: Deploy Rules

Review each rule, edit if necessary, and deploy. Deployed Suricata rules will be applied to future PCAP ingests. Deployed Sigma rules are compiled and run against existing log evidence.

### Step 9: Add Notes

Use the **Notes** page to record your analyst observations, hypotheses, and handoff notes.

### Step 10: Generate Report

Go to **Report** to generate a comprehensive investigation report. Download it as JSON for archival or sharing.

---

## Cross-Case Correlation Workflow

When investigating related incidents across multiple cases:

### Step 1: Create Individual Cases

Create and ingest evidence into separate cases for each incident.

### Step 2: Switch to Correlator Mode

On the **Dashboard**, click **Correlator**, select your source cases, create a new correlation case, and click **Apply Configuration**.

### Step 3: Run Correlation Tasks

Create tasks in the correlation case with cross-case questions:
- "Identify IOCs shared between the source cases."
- "Compare the MITRE ATT&CK techniques across all cases."
- "Determine if the same threat actor is responsible for all incidents."

The AI will analyze evidence from all source cases and identify shared indicators, overlapping techniques, and coordinated timelines.

### Step 4: Review Correlation Findings

Findings in the correlation case represent cross-case conclusions. These might reveal campaign-level patterns that aren't visible in any single case.

---

## Supported Evidence Types

### Network Traffic (PCAP Plugin)

| Tool | Record Types | Key Fields |
|------|-------------|------------|
| **Suricata** | `suricata_alert`, `suricata_http`, `suricata_dns`, `suricata_tls`, `suricata_fileinfo`, `suricata_flow`, `suricata_smtp`, `suricata_ssh` | `src_ip`, `dest_ip`, `proto`, `alert.signature`, `alert.severity` |
| **Zeek** | `zeek_conn`, `zeek_dns`, `zeek_http`, `zeek_ssl`, `zeek_files`, `zeek_x509`, `zeek_notice`, `zeek_weird`, `zeek_dhcp`, `zeek_smtp`, `zeek_ssh`, `zeek_rdp`, `zeek_pe`, `zeek_dpd`, `zeek_ntp`, `zeek_software` | `id.orig_h`, `id.resp_h`, `uid`, `service`, `duration` |
| **tshark** | `tshark_stream` | Reassembled TCP stream payloads |

### Windows Event Logs (WinEVT Plugin)

| Channel | Record Type | Key Events |
|---------|-------------|------------|
| **Security** | `win_evt_security` | 4624 (logon), 4625 (failed logon), 4648 (explicit credential use), 4672 (special privilege), 4688 (process creation) |
| **PowerShell** | `win_evt_powershell` | 4104 (script block logging — contains full PowerShell code) |
| **Sysmon** | `win_evt_sysmon` | 1 (process creation), 3 (network connection), 7 (image load), 11 (file creation), 13 (registry) |
| **Task Scheduler Operational** | `win_evt_taskscheduler` | Scheduled task registration, update, launch, and maintenance events |
| **Application** | `win_evt_application` | General application events |
| **System** | `win_evt_system` | General system events |

### Memory Forensics (Memory Plugin)

| Volatility Module | Record Type | What It Shows |
|-------------------|-------------|---------------|
| **pslist** | `vol_pslist` | Running processes (PID, PPID, name, timestamps) |
| **netscan** | `vol_netscan` | Network connections from memory (IPs, ports, state, owning process) |
| **cmdline** | `vol_cmdline` | Command-line arguments per process |
| **dlllist** | `vol_dlllist` | Loaded DLLs per process |
| **handles** | `vol_handles` | Open file/registry/mutex handles |
| **malfind** | `vol_malfind` | Suspicious memory regions (RWX permissions, injected code) |

---

## Security Model

EvidenceLab enforces security at multiple layers:

### Network Isolation

The Docker Compose stack uses two networks:

- **sphinx_internal** (no internet access) — Database and REPL containers are isolated here. The REPL container where LLM-generated code executes has no route to the internet.
- **sphinx_external** — Only the API container is exposed to the host network.

### Database Security

- **API container** connects as the `sphinx` PostgreSQL user (full access, used for migrations, user management, and ingest).
- **REPL container** connects as `sphinx_repl`, a restricted PostgreSQL role with:
  - SELECT-only on evidence tables (`records`, `entities`, `findings`, `cases`, `tasks`, `worklog_steps`, `detection_rules`)
  - INSERT/UPDATE/DELETE on `scratch_precomputed` only (needed for the `stash`/`recall` tool functions)
  - No access to admin tables (`users`, `case_assignments`, `plugin_migrations`, `background_jobs`)
- **Row-Level Security (RLS)** policies on all evidence tables enforce case-scoping at the database level. The REPL sets a session variable (`app.readable_case_ids`) at connection time, and PostgreSQL ensures queries only return rows matching the authorized case IDs.

### LLM Authentication

When an investigation task starts:

1. The system looks up the `llm_agent` service account.
2. A short-lived JWT (30-minute expiry) is minted, scoped to the relevant case(s).
3. The REPL session is initialized with the scoped case IDs, which are set as the RLS session variable on every database connection.

This ensures that even if LLM-generated code attempts to query data from other cases (e.g., via the raw `sql()` function), the database-level RLS policies prevent unauthorized access.

### Configuration

The REPL database password is configured via the `REPL_DB_PASSWORD` environment variable (default: `repl_changeme`). In production, set this to a strong random value in your `.env` file.

---

## Glossary

| Term | Definition |
|------|-----------|
| **Case** | A container for an investigation. Holds all evidence, tasks, findings, notes, and rules related to one incident. |
| **Record** | A single parsed event from an evidence source (one Suricata alert, one Windows logon event, etc.). |
| **Entity** | An indicator of compromise (IOC) extracted from records — IP addresses, domains, hashes, etc. |
| **Task** | An AI-powered investigation query. The LLM analyzes evidence and produces findings. |
| **Worklog** | The step-by-step audit trail of what the AI did during a task (code executed, results obtained). |
| **Finding** | A conclusion produced by a task, with evidence citations and MITRE ATT&CK mappings. |
| **Detection Rule** | A Suricata or Sigma rule for detecting similar attacks in the future. |
| **Precompute** | Analytics calculated before an investigation task starts, so the AI can access results instantly. |
| **RLM Loop** | Reasoning Loop with Memory — the core investigation engine where the LLM iteratively queries and analyzes evidence. |
| **Pivot** | Following an entity across records to discover relationships and patterns. |
| **MITRE ATT&CK** | A knowledge base of adversary tactics and techniques. Used to classify findings. |
| **Suricata** | An open-source network intrusion detection system (IDS). |
| **Zeek** | An open-source network analysis framework (formerly Bro). |
| **Sigma** | An open standard for log-based detection rules. |
| **Volatility** | An open-source memory forensics framework. |
| **HOME_NET** | CIDR ranges defining your internal network, used by Suricata to distinguish internal vs. external traffic. |
| **Correlator Mode** | Investigation mode for analyzing multiple cases simultaneously to find cross-case patterns. |
| **SID** | Suricata Signature ID — a unique numeric identifier for each Suricata rule. |
