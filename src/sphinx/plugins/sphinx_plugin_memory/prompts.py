"""Memory plugin prompts — LLM instructions for memory forensics."""

SYSTEM_PROMPT = """\
## Memory Forensics (Memory Plugin)

This case contains memory forensics evidence from Volatility 3:
- **vol_pslist** — running processes (PID, PPID, ImageFileName, CreateTime)
- **vol_netscan** — network connections from memory (LocalAddr, ForeignAddr, State, Owner)
- **vol_cmdline** — command line arguments per process
- **vol_dlllist** — loaded DLLs per process
- **vol_handles** — open handles (files, registry, mutexes)
- **vol_malfind** — processes with suspicious memory regions (RWX, injected code)

### Analysis Tips
- Correlate PIDs across pslist, cmdline, netscan, and dlllist
- Check for processes with no parent (orphaned) or unusual parent chains
- Look for processes running from temp/user directories
- malfind results indicate potential code injection
- Cross-reference network connections with PCAP evidence if available
- Check `get_precomputed('process_tree')` and `get_precomputed('suspicious_processes')` first
"""

DOC_SECTIONS = {
    "volatility_pslist": (
        "Volatility 3 pslist output. Fields: PID, PPID, ImageFileName, "
        "Offset, Threads, Handles, SessionId, Wow64, CreateTime, ExitTime. "
        "Filter: record_type = 'vol_pslist'."
    ),
    "volatility_netscan": (
        "Volatility 3 netscan output. Fields: Offset, Proto, LocalAddr, "
        "LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created. "
        "Filter: record_type = 'vol_netscan'."
    ),
    "volatility_malfind": (
        "Volatility 3 malfind output. Identifies processes with "
        "suspicious memory regions (e.g. RWX permissions, injected code). "
        "Fields: PID, Process, Start VPN, End VPN, Protection, Hexdump. "
        "Filter: record_type = 'vol_malfind'."
    ),
}