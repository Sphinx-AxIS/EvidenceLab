"""WinEVT plugin prompts — LLM instructions for Windows event analysis."""

SYSTEM_PROMPT = """\
## Windows Event Logs (WinEVT Plugin)

This case contains Windows Event Log evidence from one or more channels:
- **Security** (record_type: win_evt_security) — logon, privilege, audit events
- **PowerShell** (record_type: win_evt_powershell) — script execution, module loading
- **Sysmon** (record_type: win_evt_sysmon) — process creation, network, file, registry
- **Application** (record_type: win_evt_application) — application events
- **System** (record_type: win_evt_system) — service, driver, system events

### Key Event IDs
- **4624** — Successful logon (LogonType: 2=interactive, 3=network, 10=RDP)
- **4625** — Failed logon
- **4648** — Explicit credential logon
- **4672** — Special privileges assigned
- **4688** — Process creation (if audit enabled)
- **4104** — PowerShell script block logging
- **1** (Sysmon) — Process creation with full command line
- **3** (Sysmon) — Network connection
- **7** (Sysmon) — Image loaded (DLL)
- **11** (Sysmon) — File creation
- **13** (Sysmon) — Registry value set

### Query Tips
- Event data is in `raw->'EventData'->>field_name`
- EventID is at `raw->>'EventID'`
- Cast to int for numeric comparison: `(raw->>'EventID')::int`
- Channel name: `raw->>'Channel'`
- Computer name: `raw->>'Computer'`
- Check `get_precomputed('logon_summary')` and `get_precomputed('event_id_counts')` first
"""

DOC_SECTIONS = {
    "windows_security": (
        "Windows Security event log. Key EventIDs: 4624 (logon), "
        "4625 (failed logon), 4648 (explicit credential), "
        "4672 (special privilege), 4688 (process creation). "
        "EventData fields: TargetUserName, LogonType, IpAddress, "
        "WorkstationName. Filter: record_type = 'win_evt_security'."
    ),
    "windows_powershell": (
        "Windows PowerShell event log. Key EventID: 4104 (script block). "
        "ScriptBlockText contains executed PowerShell code. "
        "Filter: record_type = 'win_evt_powershell'."
    ),
    "windows_sysmon": (
        "Sysmon event log. Key EventIDs: 1 (process create), "
        "3 (network), 7 (image load), 11 (file create), "
        "13 (registry). EventData fields: Image, CommandLine, "
        "ParentImage, ProcessId, User. "
        "Filter: record_type = 'win_evt_sysmon'."
    ),
}