"""Analytics API routes — query evidence records with filtering and aggregation."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, Query

from sphinx.core.auth import CurrentUser
from sphinx.core.db import get_cursor
from sphinx.core.analytics_ops import (
    get_record_types,
    get_columns_for_type,
    extract_column_value,
    _build_where,
    _col_expr,
    value_counts as op_value_counts,
    relationships as op_relationships,
    time_series as op_time_series,
    top_n as op_top_n,
    correlate as op_correlate,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

_require_analyst = CurrentUser(required_role="analyst")


def _parse_filters(filters_json: str | None) -> list | None:
    if not filters_json:
        return None
    try:
        return json.loads(filters_json)
    except (json.JSONDecodeError, TypeError):
        return None


_RULE_MATCH_FILTER_COLUMNS = {
    "rule_id": "rule_id::text",
    "rule_title": "rule_title",
    "rule_type": "rule_type",
    "matched_record_id": "record_id::text",
    "timestamp": "ts::text",
    "channel": "channel",
    "event_id": "event_id",
}


def _build_rule_match_where(case_id: str, filters: list | None) -> tuple[str, list]:
    where_parts = ["case_id = %s"]
    params: list = [case_id]

    for filt in filters or []:
        if not isinstance(filt, dict):
            continue
        col = filt.get("col")
        op = str(filt.get("op") or "eq")
        val = filt.get("val")
        expr = _RULE_MATCH_FILTER_COLUMNS.get(col or "")
        if not expr:
            continue

        if op == "is_null":
            where_parts.append(f"({expr} IS NULL OR {expr} = '')")
            continue
        if op == "not_null":
            where_parts.append(f"({expr} IS NOT NULL AND {expr} != '')")
            continue

        val_text = str(val or "")
        if op == "eq":
            where_parts.append(f"{expr} = %s")
            params.append(val_text)
        elif op == "neq":
            where_parts.append(f"{expr} != %s")
            params.append(val_text)
        elif op == "contains":
            where_parts.append(f"LOWER(COALESCE({expr}, '')) LIKE %s")
            params.append(f"%{val_text.lower()}%")
        elif op == "gt":
            where_parts.append(f"{expr} > %s")
            params.append(val_text)
        elif op == "gte":
            where_parts.append(f"{expr} >= %s")
            params.append(val_text)
        elif op == "lt":
            where_parts.append(f"{expr} < %s")
            params.append(val_text)
        elif op == "lte":
            where_parts.append(f"{expr} <= %s")
            params.append(val_text)

    return " AND ".join(where_parts), params


def _extract_rule_match_filter(filters: list | None, key: str) -> tuple[str | None, list]:
    remaining = []
    selected = None
    for filt in filters or []:
        if isinstance(filt, dict) and filt.get("col") == key and str(filt.get("op") or "eq") == "eq" and selected is None:
            value = str(filt.get("val") or "").strip()
            if value:
                selected = value
                continue
        remaining.append(filt)
    return selected, remaining


@router.get("/summary")
async def analytics_summary(
    case_id: str = Query(...),
    user=Depends(_require_analyst),
):
    """Return record type counts for a case."""
    with get_cursor() as cur:
        types = get_record_types(cur, case_id)
        cur.execute(
            "SELECT DISTINCT entity_type FROM entities WHERE case_id = %s ORDER BY entity_type",
            (case_id,),
        )
        entity_types = [r["entity_type"] for r in cur.fetchall()]
    return {"types": types, "entity_types": entity_types}


@router.get("/columns")
async def analytics_columns(
    case_id: str = Query(...),
    record_type: str = Query(...),
    user=Depends(_require_analyst),
):
    """Return available columns for a record type (from JSONB keys)."""
    with get_cursor() as cur:
        cols = get_columns_for_type(cur, case_id, record_type)
    return {"record_type": record_type, "columns": cols}


@router.get("/query")
async def analytics_query(
    case_id: str = Query(...),
    record_type: str = Query(...),
    user=Depends(_require_analyst),
    limit: int = Query(default=200, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    filters: str | None = Query(default=None),
    sort_col: str | None = Query(default=None),
    sort_dir: str | None = Query(default="desc"),
):
    """Browse records with filters, sorting, and pagination."""
    with get_cursor() as cur:
        valid_cols = set(get_columns_for_type(cur, case_id, record_type))
        where, params = _build_where(case_id, record_type, _parse_filters(filters), valid_cols)

        # Sort
        order_expr = "ts"
        if sort_col and sort_col in valid_cols:
            order_expr = _col_expr(sort_col)
        order_dir = "ASC" if sort_dir and sort_dir.lower() == "asc" else "DESC"

        # Count
        cur.execute(f"SELECT count(*) AS cnt FROM records WHERE {where}", params)
        total = cur.fetchone()["cnt"]

        # Fetch
        display_cols = get_columns_for_type(cur, case_id, record_type)
        # Build select: system cols + raw JSONB
        sql = f"SELECT id, record_type, ts, source_plugin, raw FROM records WHERE {where} ORDER BY {order_expr} {order_dir} NULLS LAST LIMIT %s OFFSET %s"
        cur.execute(sql, params + [limit, offset])

        records = []
        for row in cur.fetchall():
            rec = {
                "id": row["id"],
                "record_type": row["record_type"],
                "ts": row["ts"].isoformat() if row["ts"] else None,
                "source_plugin": row["source_plugin"],
            }
            raw = row["raw"] if isinstance(row["raw"], dict) else (json.loads(row["raw"]) if row["raw"] else {})
            for key in display_cols:
                if key in rec:
                    continue
                val = extract_column_value(raw, key)
                if val is not None:
                    if hasattr(val, "isoformat"):
                        val = val.isoformat()
                    rec[key] = val
            records.append(rec)

    return {
        "record_type": record_type,
        "columns": display_cols,
        "records": records,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/value-counts")
async def analytics_value_counts(
    case_id: str = Query(...),
    record_type: str = Query(...),
    column: str = Query(...),
    user=Depends(_require_analyst),
    limit: int = Query(default=50, ge=1, le=1000),
    filters: str | None = Query(default=None),
):
    try:
        with get_cursor() as cur:
            return op_value_counts(
                cur, case_id, record_type, column,
                filters=_parse_filters(filters), limit=limit,
            )
    except ValueError as e:
        return {"error": str(e)}


@router.get("/relationships")
async def analytics_relationships(
    case_id: str = Query(...),
    record_type: str = Query(...),
    col_a: str = Query(...),
    col_b: str = Query(...),
    user=Depends(_require_analyst),
    limit: int = Query(default=100, ge=1, le=5000),
    filters: str | None = Query(default=None),
):
    try:
        with get_cursor() as cur:
            return op_relationships(
                cur, case_id, record_type, col_a, col_b,
                filters=_parse_filters(filters), limit=limit,
            )
    except ValueError as e:
        return {"error": str(e)}


@router.get("/time-series")
async def analytics_time_series(
    case_id: str = Query(...),
    record_type: str = Query(...),
    interval: str = Query(default="hour"),
    group_col: str | None = Query(default=None),
    user=Depends(_require_analyst),
    limit: int = Query(default=500, ge=1, le=5000),
    filters: str | None = Query(default=None),
):
    try:
        with get_cursor() as cur:
            return op_time_series(
                cur, case_id, record_type, interval=interval,
                group_col=group_col or None,
                filters=_parse_filters(filters), limit=limit,
            )
    except ValueError as e:
        return {"error": str(e)}


@router.get("/top-n")
async def analytics_top_n(
    case_id: str = Query(...),
    record_type: str = Query(...),
    group_col: str = Query(...),
    metric_col: str | None = Query(default=None),
    agg_func: str = Query(default="count"),
    user=Depends(_require_analyst),
    limit: int = Query(default=20, ge=1, le=1000),
    filters: str | None = Query(default=None),
):
    try:
        with get_cursor() as cur:
            return op_top_n(
                cur, case_id, record_type, group_col,
                metric_col=metric_col or None,
                agg_func=agg_func,
                filters=_parse_filters(filters), limit=limit,
            )
    except ValueError as e:
        return {"error": str(e)}


@router.get("/correlate")
async def analytics_correlate(
    case_id: str = Query(...),
    type_a: str = Query(...),
    type_b: str = Query(...),
    window_seconds: int = Query(default=300, ge=1, le=86400),
    entity_type: str | None = Query(default=None),
    user=Depends(_require_analyst),
    limit: int = Query(default=100, ge=1, le=5000),
):
    """Find correlated events across two record types by timestamp proximity."""
    try:
        with get_cursor() as cur:
            return op_correlate(
                cur, case_id, type_a, type_b,
                window_seconds=window_seconds,
                entity_type=entity_type or None,
                limit=limit,
            )
    except ValueError as e:
        return {"error": str(e)}


@router.get("/rule-matches")
async def analytics_rule_matches(
    case_id: str = Query(...),
    user=Depends(_require_analyst),
    limit: int = Query(default=200, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    filters: str | None = Query(default=None),
    sort_col: str | None = Query(default="timestamp"),
    sort_dir: str | None = Query(default="desc"),
):
    from sphinx.core.sig_generator import _compile_sigma_rule_for_test

    sort_expr_map = {
        "rule_title": "rule_title",
        "rule_type": "rule_type",
        "matched_record_id": "record_id",
        "timestamp": "ts",
        "channel": "channel",
        "event_id": "event_id",
    }
    order_expr = sort_expr_map.get(sort_col or "timestamp", "ts")
    order_dir = "ASC" if sort_dir and sort_dir.lower() == "asc" else "DESC"

    filters_data = _parse_filters(filters)
    selected_rule_id, remaining_filters = _extract_rule_match_filter(filters_data, "rule_id")

    if selected_rule_id:
        with get_cursor() as cur:
            cur.execute(
                """
                SELECT id, title, rule_type, rule_content, compiled_sql, sid, status
                FROM detection_rules
                WHERE id = %s AND (case_id = %s OR case_id = '' OR case_id IS NULL)
                """,
                (selected_rule_id, case_id),
            )
            rule = cur.fetchone()

        if not rule:
            return {"error": "Selected rule was not found for this case."}

        if rule["rule_type"] == "sigma":
            compiled_sql = rule.get("compiled_sql") or ""
            if not compiled_sql:
                compiled_sql = _compile_sigma_rule_for_test(rule["rule_content"], rule)
            if not compiled_sql:
                return {"error": "Selected Sigma rule could not be compiled to SQL."}
            subquery = f"""
                SELECT
                    {int(rule['id'])} AS rule_id,
                    '{str(rule['title']).replace("'", "''")}' AS rule_title,
                    'sigma' AS rule_type,
                    id AS record_id,
                    record_type,
                    ts,
                    COALESCE(raw->>'Channel', '') AS channel,
                    COALESCE(raw->>'EventID', '') AS event_id
                FROM ({compiled_sql}) AS matched_records
                WHERE case_id = %s
            """
            base_params = [case_id]
        else:
            sid = rule.get("sid")
            if not sid:
                return {"error": "Selected Suricata rule does not have a SID, so it cannot be mapped to case alert records."}
            subquery = f"""
                SELECT
                    {int(rule['id'])} AS rule_id,
                    '{str(rule['title']).replace("'", "''")}' AS rule_title,
                    'suricata' AS rule_type,
                    id AS record_id,
                    record_type,
                    ts,
                    '' AS channel,
                    COALESCE(raw->'alert'->>'signature_id', '') AS event_id
                FROM records
                WHERE case_id = %s
                  AND record_type = 'suricata_alert'
                  AND raw->'alert'->>'signature_id' = %s
            """
            base_params = [case_id, str(sid)]

        where, extra_params = _build_rule_match_where(case_id, remaining_filters)
        if where == "case_id = %s":
            where = "TRUE"
            trailing_params: list = []
        else:
            where = where.replace("case_id = %s AND ", "", 1)
            trailing_params = extra_params[1:]

        with get_cursor() as cur:
            cur.execute(
                f"SELECT count(*) AS cnt FROM ({subquery}) AS rule_hits WHERE {where}",
                base_params + trailing_params,
            )
            total = cur.fetchone()["cnt"]

            cur.execute(
                f"SELECT max(ts) AS latest_match FROM ({subquery}) AS rule_hits WHERE {where}",
                base_params + trailing_params,
            )
            latest_match_row = cur.fetchone()

            cur.execute(
                f"""
                SELECT
                    rule_id,
                    rule_title,
                    rule_type,
                    record_id,
                    record_type,
                    ts,
                    channel,
                    event_id
                FROM ({subquery}) AS rule_hits
                WHERE {where}
                ORDER BY {order_expr} {order_dir} NULLS LAST, rule_title ASC
                LIMIT %s OFFSET %s
                """,
                base_params + trailing_params + [limit, offset],
            )
            rows = cur.fetchall()

        matches = []
        for row in rows:
            ts = row.get("ts")
            matches.append({
                "rule_id": row["rule_id"],
                "rule_title": row["rule_title"],
                "rule_type": row["rule_type"],
                "matched_record_id": row["record_id"],
                "record_type": row["record_type"],
                "timestamp": ts.isoformat() if ts else None,
                "channel": row.get("channel") or "",
                "event_id": row.get("event_id") or "",
            })

        latest_match = latest_match_row.get("latest_match") if latest_match_row else None
        latest_match_text = latest_match.isoformat() if latest_match else None
        return {
            "operation": "rule_matches",
            "matches": matches,
            "total": total,
            "limit": limit,
            "offset": offset,
            "summary": {
                "total_matches": total,
                "unique_rules": 1,
                "latest_match": latest_match_text,
            },
            "columns": [
                "timestamp",
                "rule_title",
                "rule_type",
                "matched_record_id",
                "channel",
                "event_id",
            ],
        }

    subquery = """
        SELECT
            dm.case_id,
            dm.rule_id,
            dm.rule_title,
            dm.rule_type,
            dm.record_id,
            dm.record_type,
            dm.ts,
            dm.channel,
            dm.event_id
        FROM detection_matches dm
        UNION ALL
        SELECT
            r.case_id,
            dr.id AS rule_id,
            dr.title AS rule_title,
            'suricata' AS rule_type,
            r.id AS record_id,
            r.record_type,
            r.ts,
            '' AS channel,
            COALESCE(r.raw->'alert'->>'signature_id', '') AS event_id
        FROM records r
        JOIN detection_rules dr
          ON dr.rule_type = 'suricata'
         AND dr.sid IS NOT NULL
         AND dr.sid = COALESCE((r.raw->'alert'->>'signature_id')::int, -1)
        WHERE r.record_type = 'suricata_alert'
    """

    where, params = _build_rule_match_where(case_id, filters_data)

    with get_cursor() as cur:
        cur.execute(
            f"SELECT count(*) AS cnt FROM ({subquery}) AS rule_hits WHERE {where}",
            params,
        )
        total = cur.fetchone()["cnt"]

        cur.execute(
            f"SELECT count(DISTINCT rule_id) AS cnt FROM ({subquery}) AS rule_hits WHERE {where}",
            params,
        )
        unique_rules_total = cur.fetchone()["cnt"]

        cur.execute(
            f"SELECT max(ts) AS latest_match FROM ({subquery}) AS rule_hits WHERE {where}",
            params,
        )
        latest_match_row = cur.fetchone()

        cur.execute(
            f"""
            SELECT
                rule_id,
                rule_title,
                rule_type,
                record_id,
                record_type,
                ts,
                channel,
                event_id
            FROM ({subquery}) AS rule_hits
            WHERE {where}
            ORDER BY {order_expr} {order_dir} NULLS LAST, rule_title ASC
            LIMIT %s OFFSET %s
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()

    matches = []
    for row in rows:
        ts = row.get("ts")
        ts_text = ts.isoformat() if ts else None
        matches.append({
            "rule_id": row["rule_id"],
            "rule_title": row["rule_title"],
            "rule_type": row["rule_type"],
            "matched_record_id": row["record_id"],
            "record_type": row["record_type"],
            "timestamp": ts_text,
            "channel": row.get("channel") or "",
            "event_id": row.get("event_id") or "",
        })

    latest_match = latest_match_row.get("latest_match") if latest_match_row else None
    latest_match_text = latest_match.isoformat() if latest_match else None

    return {
        "operation": "rule_matches",
        "matches": matches,
        "total": total,
        "limit": limit,
        "offset": offset,
        "summary": {
            "total_matches": total,
            "unique_rules": unique_rules_total,
            "latest_match": latest_match_text,
        },
        "columns": [
            "timestamp",
            "rule_title",
            "rule_type",
            "matched_record_id",
            "channel",
            "event_id",
        ],
    }


@router.get("/rule-match-metadata")
async def analytics_rule_match_metadata(
    case_id: str = Query(...),
    user=Depends(_require_analyst),
):
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT id AS rule_id, title AS rule_title, rule_type, status
            FROM detection_rules
            WHERE case_id = %s OR case_id = '' OR case_id IS NULL
            ORDER BY title ASC
            """,
            (case_id,),
        )
        rules = cur.fetchall()

    return {
        "rules": [
            {
                "rule_id": row["rule_id"],
                "rule_title": row["rule_title"],
                "rule_type": row["rule_type"],
                "status": row["status"],
            }
            for row in rules
        ]
    }
