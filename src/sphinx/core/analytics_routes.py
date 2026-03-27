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

        # Build WHERE
        conditions = ["case_id = %s", "record_type = %s"]
        params: list = [case_id, record_type]

        if filters:
            from sphinx.core.analytics_ops import OPS, _col_expr
            filter_list = _parse_filters(filters) or []
            for f in filter_list:
                col = f.get("col", "")
                op = f.get("op", "eq")
                val = f.get("val", "")
                if col not in valid_cols or op not in OPS:
                    continue
                expr = _col_expr(col)
                if op in ("is_null", "not_null"):
                    conditions.append(f"{expr} {OPS[op]}")
                elif op == "contains":
                    conditions.append(f"{expr} ILIKE %s")
                    params.append(f"%{val}%")
                else:
                    conditions.append(f"{expr} {OPS[op]}")
                    params.append(str(val))

        where = " AND ".join(conditions)

        # Sort
        from sphinx.core.analytics_ops import _col_expr
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
