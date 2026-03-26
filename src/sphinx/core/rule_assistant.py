"""Deterministic rule-assistance helpers for Sigma and Suricata authoring."""

from __future__ import annotations

import re
from typing import Any

from sphinx.core.db import get_cursor


_GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)
_SID_RE = re.compile(r"^S-\d-(?:\d+-){1,14}\d+$", re.IGNORECASE)
_HEXISH_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_WINDOWS_RECOMMENDED_KEYS = {
    "Image": "Process image paths are often stable Sigma anchors for suspicious execution.",
    "ParentImage": "Parent-child process lineage is often useful for behavioral detection.",
    "CommandLine": "Command-line content can be valuable when it captures suspicious operator behavior.",
    "ScriptBlockText": "Script block content is highly relevant for PowerShell detection.",
    "ServiceName": "Service names are often useful when detecting persistence or service abuse.",
    "TaskName": "Task names are useful anchors for scheduled task detections.",
    "TargetObject": "Registry or object targets can be useful when detecting persistence or tampering.",
    "ObjectName": "Object names can help anchor file, service, or registry-related behaviors.",
    "PipeName": "Named pipe values can be strong anchors for certain lateral movement or tooling patterns.",
    "DestinationHostname": "Destination hostnames can help when a behavior is tied to stable network targets.",
}

_WINDOWS_OPTIONAL_KEYS = {
    "IpAddress": "Source IPs can help narrow scope, but may be environment-specific.",
    "WorkstationName": "Workstation names can add context, but are often too environment-specific for the main selector.",
    "ParentCommandLine": "Parent command lines can help, but often require careful scoping to avoid noise.",
    "TargetUserName": "Usernames can be useful context, but often create brittle detections.",
    "SubjectUserName": "Usernames can be useful context, but often create brittle detections.",
    "TargetDomainName": "Domain values can help with scoping, but may not generalize well.",
    "DestinationIp": "Destination IPs may be useful for IOC-style detection, but are often brittle.",
    "SourceIp": "Source IPs may help scope an alert, but are often too environment-specific.",
}

_WINDOWS_AVOID_KEYS = {
    "Computer": "Hostnames usually identify a specific machine rather than a durable behavior.",
    "Workstation": "Hostnames usually identify a specific machine rather than a durable behavior.",
    "SubjectLogonId": "Logon IDs are session-specific and not stable detection anchors.",
    "LogonId": "Logon IDs are session-specific and not stable detection anchors.",
    "ProcessId": "Process IDs are ephemeral and should not anchor a rule.",
    "ThreadId": "Thread IDs are ephemeral and should not anchor a rule.",
    "TargetLogonId": "Logon IDs are session-specific and not stable detection anchors.",
    "UserSid": "SIDs are often too environment-specific for the main selector.",
    "SubjectUserSid": "SIDs are often too environment-specific for the main selector.",
    "TargetUserSid": "SIDs are often too environment-specific for the main selector.",
}

_NETWORK_RECOMMENDED_KEYS = {
    "http.host": "HTTP host values are visible on the wire and often useful in Suricata rules.",
    "host": "HTTP host values are visible on the wire and often useful in Suricata rules.",
    "http.uri": "HTTP URI patterns can be good content anchors when they are stable and distinctive.",
    "uri": "HTTP URI patterns can be good content anchors when they are stable and distinctive.",
    "dns.query": "DNS queries are directly visible on the wire and map well to Suricata DNS rules.",
    "query": "DNS queries are directly visible on the wire and map well to Suricata DNS rules.",
    "tls.sni": "TLS SNI values are often a better anchor than raw IPs for encrypted traffic.",
    "server_name": "TLS SNI values are often a better anchor than raw IPs for encrypted traffic.",
    "alert_signature": "Existing alert signatures can help identify what packet-visible behavior stood out.",
    "ascii_printable": "Stable printable payload strings can often become Suricata content matches.",
    "stream_text": "Stable printable payload strings can often become Suricata content matches.",
}

_NETWORK_OPTIONAL_KEYS = {
    "src_ip": "Source IPs are visible on the wire, but often too environment-specific for a durable rule.",
    "dest_ip": "Destination IPs are visible on the wire, but often better treated as IOC context.",
    "service": "Protocol or service hints can help scope the rule, but usually need another anchor.",
    "method": "HTTP methods help scope a rule, but rarely stand on their own.",
}

_NETWORK_AVOID_KEYS = {
    "uid": "Session identifiers are tool-generated metadata rather than packet-visible detection anchors.",
    "flow_id": "Flow IDs are tool-generated metadata rather than durable anchors.",
    "id.orig_h": "Connection endpoint IPs are often too environment-specific for the main selector.",
    "id.resp_h": "Connection endpoint IPs are often too environment-specific for the main selector.",
}


def _short(value: Any, limit: int = 120) -> str:
    text = str(value).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _is_dynamic_value(value: str) -> bool:
    value = value.strip()
    if not value:
        return True
    if _GUID_RE.fullmatch(value) or _SID_RE.fullmatch(value):
        return True
    if _HEXISH_RE.fullmatch(value) and len(value) >= 16:
        return True
    if value.endswith("$") and "\\" not in value:
        return True
    return False


def _windows_field_stats(case_id: str, record_type: str, event_id: str, key: str, value: str) -> tuple[int, int]:
    if not event_id:
        return 0, 0
    with get_cursor() as cur:
        cur.execute(
            f"""SELECT count(*) AS n
                FROM records
                WHERE case_id = %s
                  AND record_type = %s
                  AND COALESCE(raw->>'EventID', '') = %s
                  AND COALESCE(raw->'EventData'->>'{key}', '') <> ''""",
            (case_id, record_type, event_id),
        )
        present_count = cur.fetchone()["n"]
        cur.execute(
            f"""SELECT count(*) AS n
                FROM records
                WHERE case_id = %s
                  AND record_type = %s
                  AND COALESCE(raw->>'EventID', '') = %s
                  AND COALESCE(raw->'EventData'->>'{key}', '') = %s""",
            (case_id, record_type, event_id, value),
        )
        exact_count = cur.fetchone()["n"]
    return present_count, exact_count


def _network_field_stats(case_id: str, record_type: str, key: str, value: str) -> tuple[int, int]:
    with get_cursor() as cur:
        cur.execute(
            f"""SELECT count(*) AS n
                FROM records
                WHERE case_id = %s
                  AND record_type = %s
                  AND COALESCE(raw->>'{key}', '') <> ''""",
            (case_id, record_type),
        )
        present_count = cur.fetchone()["n"]
        cur.execute(
            f"""SELECT count(*) AS n
                FROM records
                WHERE case_id = %s
                  AND record_type = %s
                  AND COALESCE(raw->>'{key}', '') = %s""",
            (case_id, record_type, value),
        )
        exact_count = cur.fetchone()["n"]
    return present_count, exact_count


def _build_item(field: str, value: str, reason: str, present_count: int = 0, exact_count: int = 0) -> dict[str, str]:
    prevalence = ""
    if present_count or exact_count:
        prevalence = f"Seen in {exact_count} matching records; field appears in {present_count} similar records."
    return {
        "field": field,
        "value": _short(value),
        "reason": reason,
        "prevalence": prevalence,
        "present_count": str(present_count),
        "exact_count": str(exact_count),
    }


def _recommend_windows(case_id: str, record_type: str, raw: dict[str, Any]) -> dict[str, Any]:
    event_id = str(raw.get("EventID") or "").strip()
    channel = str(raw.get("Channel") or "").strip()
    provider = str(raw.get("Provider") or "").strip()
    event_data = raw.get("EventData") if isinstance(raw.get("EventData"), dict) else {}

    with get_cursor() as cur:
        cur.execute(
            "SELECT count(*) AS n FROM records WHERE case_id = %s AND record_type = %s AND COALESCE(raw->>'EventID', '') = %s",
            (case_id, record_type, event_id),
        )
        family_count = cur.fetchone()["n"] if event_id else 0

    recommended: list[dict[str, str]] = []
    optional: list[dict[str, str]] = []
    avoid: list[dict[str, str]] = []

    if channel:
        recommended.append(_build_item(
            "Channel",
            channel,
            "Channel selection helps scope the Sigma logsource correctly.",
            family_count,
            family_count,
        ))
    if event_id:
        recommended.append(_build_item(
            "EventID",
            event_id,
            "EventID is the primary selector for most Windows-event Sigma rules.",
            family_count,
            family_count,
        ))
    if provider:
        optional.append(_build_item(
            "Provider",
            provider,
            "Provider can help with context, but EventID and EventData fields usually carry more detection value.",
            family_count,
            family_count,
        ))

    for key, raw_value in event_data.items():
        if not isinstance(raw_value, str):
            continue
        value = raw_value.strip()
        if not value:
            continue

        present_count, exact_count = _windows_field_stats(case_id, record_type, event_id, key, value)
        field_name = f"EventData.{key}"

        if key in _WINDOWS_AVOID_KEYS or _is_dynamic_value(value):
            reason = _WINDOWS_AVOID_KEYS.get(key, "This value looks environment-specific or ephemeral rather than behavior-based.")
            avoid.append(_build_item(field_name, value, reason, present_count, exact_count))
            continue

        if key in _WINDOWS_RECOMMENDED_KEYS:
            reason = _WINDOWS_RECOMMENDED_KEYS[key]
            if exact_count <= 1 and present_count > 5:
                optional.append(_build_item(field_name, value, reason + " This exact value appears only once in the current event family, so review it before anchoring the rule on it.", present_count, exact_count))
            else:
                recommended.append(_build_item(field_name, value, reason, present_count, exact_count))
            continue

        if key in _WINDOWS_OPTIONAL_KEYS:
            optional.append(_build_item(field_name, value, _WINDOWS_OPTIONAL_KEYS[key], present_count, exact_count))
            continue

        if len(value) > 160:
            avoid.append(_build_item(field_name, value, "This value is long and likely too specific for a stable selector without careful refinement.", present_count, exact_count))
            continue

        if value.isdigit():
            avoid.append(_build_item(field_name, value, "Pure numeric values are often too generic or ephemeral without more context.", present_count, exact_count))
            continue

        optional.append(_build_item(field_name, value, "This field may help, but it is not a common first-choice Sigma anchor. Review its stability before using it.", present_count, exact_count))

    return {
        "rule_family": "sigma",
        "headline": "Deterministic Sigma field recommendations",
        "summary": "EvidenceLab ranked the selected Windows-event fields by how suitable they are as stable Sigma selectors.",
        "recommended": recommended[:8],
        "optional": optional[:10],
        "avoid": avoid[:10],
    }


def _recommend_network(case_id: str, record_type: str, raw: dict[str, Any]) -> dict[str, Any]:
    recommended: list[dict[str, str]] = []
    optional: list[dict[str, str]] = []
    avoid: list[dict[str, str]] = []

    for key, raw_value in raw.items():
        if not isinstance(raw_value, str):
            continue
        value = raw_value.strip()
        if not value:
            continue

        present_count, exact_count = _network_field_stats(case_id, record_type, key, value)

        if key in _NETWORK_AVOID_KEYS:
            avoid.append(_build_item(key, value, _NETWORK_AVOID_KEYS[key], present_count, exact_count))
            continue

        if key in _NETWORK_RECOMMENDED_KEYS:
            recommended.append(_build_item(key, value, _NETWORK_RECOMMENDED_KEYS[key], present_count, exact_count))
            continue

        if key in _NETWORK_OPTIONAL_KEYS or _IPV4_RE.fullmatch(value):
            reason = _NETWORK_OPTIONAL_KEYS.get(key, "This value may help scope a Suricata rule, but it is often better as supporting context than as the main anchor.")
            optional.append(_build_item(key, value, reason, present_count, exact_count))
            continue

        if len(value) > 180:
            avoid.append(_build_item(key, value, "This value is long and may be too session-specific for a durable packet signature.", present_count, exact_count))
            continue

        optional.append(_build_item(key, value, "This field may help, but confirm that it is packet-visible and stable before using it in a Suricata rule.", present_count, exact_count))

    return {
        "rule_family": "suricata",
        "headline": "Deterministic Suricata field recommendations",
        "summary": "EvidenceLab ranked the selected network-derived fields by how suitable they are as packet-visible Suricata anchors.",
        "recommended": recommended[:8],
        "optional": optional[:10],
        "avoid": avoid[:10],
    }


def build_rule_recommendations(case_id: str, record_type: str, raw: dict[str, Any] | None) -> dict[str, Any]:
    """Return deterministic rule-authoring recommendations for a selected record."""
    raw = raw or {}
    if record_type.startswith("win_evt_"):
        return _recommend_windows(case_id, record_type, raw)
    if record_type.startswith(("suricata_", "zeek_", "tshark_")):
        return _recommend_network(case_id, record_type, raw)
    return {
        "rule_family": "",
        "headline": "Deterministic rule recommendations",
        "summary": "No deterministic rule recommendations are available for this record type yet.",
        "recommended": [],
        "optional": [],
        "avoid": [],
    }
