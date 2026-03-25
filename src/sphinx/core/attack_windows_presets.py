"""Load Windows ATT&CK starter filters from the local mapping dataset."""

from __future__ import annotations

import csv
import re
from pathlib import Path


_DATA_PATH = Path(__file__).resolve().parents[3] / "data" / "filtered_mitre_mappings.csv"


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.strip().lower())
    return value.strip("-")


def _technique_url(technique_id: str) -> str:
    tid = (technique_id or "").strip().upper()
    if "." in tid:
        base, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def _load_attack_windows_presets() -> list[dict[str, object]]:
    if not _DATA_PATH.exists():
        return []

    grouped: dict[tuple[str, str, str, str], dict[str, object]] = {}

    with _DATA_PATH.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            tactic = (row.get("tactic") or "").strip()
            technique_id = (row.get("technique_id") or "").strip()
            technique = (row.get("technique") or "").strip()
            event_id = (row.get("event_id") or "").strip()
            audit_category = (row.get("audit_category") or "").strip()
            audit_sub_category = (row.get("audit_sub_category") or "").strip()
            message = (row.get("message") or "").strip()

            if not (tactic and technique_id and technique and event_id):
                continue

            key = (tactic, technique_id, technique, event_id)
            preset = grouped.get(key)
            if preset is None:
                summary_parts = [part for part in (audit_category, audit_sub_category, message) if part]
                preset = {
                    "id": f"attack-{_slug(tactic)}-{_slug(technique_id)}-{event_id}",
                    "title": technique,
                    "tactic": tactic,
                    "technique_id": technique_id,
                    "technique_name": technique,
                    "detection_strategy_id": "",
                    "record_type": "win_evt_security",
                    "channels": ["Security"],
                    "event_ids": [event_id],
                    "filters": [
                        {"col": "Channel", "op": "eq", "val": "Security"},
                        {"col": "EventID", "op": "eq", "val": event_id},
                    ],
                    "summary": " | ".join(summary_parts),
                    "source_url": _technique_url(technique_id),
                }
                grouped[key] = preset
            elif message:
                existing_summary = str(preset.get("summary") or "")
                if message not in existing_summary:
                    preset["summary"] = (existing_summary + " | " + message).strip(" |")

    presets = list(grouped.values())
    presets.sort(key=lambda item: (str(item["tactic"]), str(item["technique_id"]), str(item["event_ids"][0])))
    return presets


ATTACK_WINDOWS_PRESETS = _load_attack_windows_presets()
