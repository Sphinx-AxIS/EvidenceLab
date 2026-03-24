"""Windows EVTX parsing helpers.

Parses raw ``.evtx`` files into normalized dict records that match the
existing ``win_evt_*`` ingest handler expectations:

- top-level ``EventID``
- top-level ``Channel``
- top-level ``Computer``
- top-level ``Provider``
- nested ``EventData`` for Sigma-friendly field access

The normalized shape is intentionally stable so junior analysts can inspect a
record in the UI and use those same field names when authoring Sigma rules.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from xml.etree import ElementTree as ET


_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _text(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    return "".join(elem.itertext()).strip()


def _maybe_int(value: str) -> int | str:
    value = value.strip()
    if not value:
        return ""
    if value.isdigit():
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _add_value(target: dict[str, Any], key: str, value: Any) -> None:
    if key not in target:
        target[key] = value
        return
    existing = target[key]
    if isinstance(existing, list):
        existing.append(value)
    else:
        target[key] = [existing, value]


def _parse_children(elem: ET.Element) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for child in list(elem):
        tag = child.tag.rsplit("}", 1)[-1]
        if list(child):
            value = _parse_children(child)
        else:
            value = _text(child)
        if child.attrib:
            if isinstance(value, dict):
                if "#attrs" not in value:
                    value["#attrs"] = {}
                value["#attrs"].update(child.attrib)
            elif value:
                value = {"#text": value, "#attrs": dict(child.attrib)}
            else:
                value = dict(child.attrib)
        _add_value(out, tag, value)
    return out


def _parse_event_xml(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)

    system = root.find("e:System", _NS)
    system_data: dict[str, Any] = {}

    provider_name = ""
    event_id: int | str = ""
    channel = ""
    computer = ""
    system_time = ""

    if system is not None:
        provider = system.find("e:Provider", _NS)
        if provider is not None:
            provider_name = provider.attrib.get("Name", "")
            system_data["Provider"] = dict(provider.attrib)

        event_id_elem = system.find("e:EventID", _NS)
        if event_id_elem is not None:
            event_id = _maybe_int(_text(event_id_elem))
            system_data["EventID"] = event_id
            if event_id_elem.attrib:
                system_data["EventIDAttributes"] = dict(event_id_elem.attrib)

        for tag in ("Version", "Level", "Task", "Opcode", "Keywords", "EventRecordID", "Channel", "Computer"):
            child = system.find(f"e:{tag}", _NS)
            if child is None:
                continue
            value = _text(child)
            if value:
                system_data[tag] = _maybe_int(value)

        time_created = system.find("e:TimeCreated", _NS)
        if time_created is not None:
            system_time = time_created.attrib.get("SystemTime", "")
            system_data["TimeCreated"] = dict(time_created.attrib)

        execution = system.find("e:Execution", _NS)
        if execution is not None and execution.attrib:
            system_data["Execution"] = dict(execution.attrib)

        correlation = system.find("e:Correlation", _NS)
        if correlation is not None and correlation.attrib:
            system_data["Correlation"] = dict(correlation.attrib)

        security = system.find("e:Security", _NS)
        if security is not None and security.attrib:
            system_data["Security"] = dict(security.attrib)

        channel = str(system_data.get("Channel", ""))
        computer = str(system_data.get("Computer", ""))

    event_data: dict[str, Any] = {}
    event_data_elem = root.find("e:EventData", _NS)
    if event_data_elem is not None:
        unnamed_idx = 0
        for child in list(event_data_elem):
            tag = child.tag.rsplit("}", 1)[-1]
            key = child.attrib.get("Name") or child.attrib.get("name")
            if not key:
                unnamed_idx += 1
                key = f"{tag}_{unnamed_idx}"
            value = _text(child)
            if child.attrib and "Name" not in child.attrib and "name" not in child.attrib:
                if value:
                    value = {"#text": value, "#attrs": dict(child.attrib)}
                else:
                    value = dict(child.attrib)
            _add_value(event_data, key, value)

    user_data: dict[str, Any] = {}
    user_data_elem = root.find("e:UserData", _NS)
    if user_data_elem is not None:
        user_data = _parse_children(user_data_elem)

    rendering_info: dict[str, Any] = {}
    rendering_elem = root.find("e:RenderingInfo", _NS)
    if rendering_elem is not None:
        rendering_info = _parse_children(rendering_elem)

    record: dict[str, Any] = {
        "EventID": event_id,
        "Channel": channel,
        "Computer": computer,
        "Provider": provider_name,
        "SystemTime": system_time,
        "timestamp": system_time,
        "System": system_data,
    }
    if "EventRecordID" in system_data:
        record["EventRecordID"] = system_data["EventRecordID"]
    if event_data:
        record["EventData"] = event_data
    if user_data:
        record["UserData"] = user_data
    if rendering_info:
        record["RenderingInfo"] = rendering_info
        message = rendering_info.get("Message")
        if isinstance(message, str) and message.strip():
            record["Message"] = message.strip()

    return record


def classify_channel(channel: str) -> str | None:
    value = (channel or "").strip().lower()
    if value == "security":
        return "win_evt_security"
    if "powershell" in value:
        return "win_evt_powershell"
    if "sysmon" in value:
        return "win_evt_sysmon"
    if value == "application":
        return "win_evt_application"
    if value == "system":
        return "win_evt_system"
    return None


def parse_evtx(path: str) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    """Parse an EVTX file into grouped handler payloads.

    Returns:
        grouped_records: {record_type: [normalized_event_dict, ...]}
        stats: summary counters for UI messaging
    """
    from Evtx.Evtx import Evtx

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    stats = {
        "total_events": 0,
        "supported_events": 0,
        "unsupported_events": 0,
        "parse_errors": 0,
    }

    with Evtx(path) as log:
        for record in log.records():
            stats["total_events"] += 1
            try:
                normalized = _parse_event_xml(record.xml())
                record_type = classify_channel(str(normalized.get("Channel", "")))
                if not record_type:
                    stats["unsupported_events"] += 1
                    continue
                grouped[record_type].append(normalized)
                stats["supported_events"] += 1
            except Exception:
                stats["parse_errors"] += 1

    return dict(grouped), stats
