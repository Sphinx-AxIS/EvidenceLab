"""Generic analytics operations over evidence records.

Each function takes (cur, case_id, record_type, ...) and returns a dict.
Operates on the records table, extracting columns from the JSONB raw field.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import psycopg

# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

OPS = {
    "eq": "= %s",
    "neq": "!= %s",
    "contains": "ILIKE %s",
    "gt": "> %s",
    "gte": ">= %s",
    "lt": "< %s",
    "lte": "<= %s",
    "is_null": "IS NULL",
    "not_null": "IS NOT NULL",
}

VALID_INTERVALS = {"minute", "hour", "day", "week"}
VALID_AGG_FUNCS = {"count", "sum", "avg", "min", "max", "count_distinct"}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def get_record_types(cur: psycopg.Cursor, case_id: str) -> List[Dict[str, Any]]:
    """Return record types with counts for a case."""
    cur.execute(
        """SELECT record_type, count(*)::int AS count
           FROM records WHERE case_id = %s
           GROUP BY record_type ORDER BY count DESC""",
        (case_id,),
    )
    return [{"type": r[0], "count": r[1]} for r in cur.fetchall()]


def get_columns_for_type(cur: psycopg.Cursor, case_id: str, record_type: str) -> List[str]:
    """Discover available columns by sampling raw JSONB keys.

    Samples up to 50 records and unions all top-level keys.
    Always includes system columns: id, record_type, ts, source_plugin.
    """
    cur.execute(
        """SELECT DISTINCT jsonb_object_keys(raw) AS key
           FROM (
               SELECT raw FROM records
               WHERE case_id = %s AND record_type = %s
               LIMIT 50
           ) sub""",
        (case_id, record_type),
    )
    json_keys = sorted(r[0] for r in cur.fetchall())
    # Prepend system columns
    system_cols = ["id", "record_type", "ts", "source_plugin"]
    return system_cols + json_keys


def _col_expr(col: str) -> str:
    """Return SQL expression for a column name.

    System columns (id, record_type, ts, source_plugin) are real columns.
    Everything else is extracted from raw JSONB with ->> operator.
    """
    if col in ("id", "record_type", "ts", "source_plugin", "case_id"):
        return f'"{col}"'
    return f"(raw->>'{col}')"


def _build_where(
    case_id: str,
    record_type: str,
    filters: Optional[List[Dict[str, str]]],
    valid_cols: set,
) -> Tuple[str, list]:
    """Build WHERE clause and params from filter list."""
    conditions = ["case_id = %s", "record_type = %s"]
    params: list = [case_id, record_type]

    if filters:
        for f in filters:
            col = f.get("col", "")
            op = f.get("op", "eq")
            val = f.get("val", "")
            if col not in valid_cols or op not in OPS:
                continue
            expr = _col_expr(col)
            if op in ("is_null", "not_null"):
                conditions.append(f"{expr} {OPS[op]}")
            elif op == "contains":
                conditions.append(f"{expr} {OPS[op]}")
                params.append(f"%{val}%")
            else:
                conditions.append(f"{expr} {OPS[op]}")
                params.append(str(val))

    return " AND ".join(conditions), params


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def value_counts(
    cur: psycopg.Cursor,
    case_id: str,
    record_type: str,
    column: str,
    filters: Optional[List[Dict[str, str]]] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """GROUP BY one column, return values with counts, ordered by count DESC."""
    valid_cols = set(get_columns_for_type(cur, case_id, record_type))
    if column not in valid_cols:
        raise ValueError(f"Invalid column: {column}")

    where, params = _build_where(case_id, record_type, filters, valid_cols)
    col_expr = _col_expr(column)

    sql = (
        f"SELECT {col_expr}::text AS value, COUNT(*)::int AS count "
        f"FROM records WHERE {where} "
        f"GROUP BY 1 ORDER BY count DESC LIMIT %s"
    )
    params.append(limit)
    cur.execute(sql, params)
    rows = [{"value": r[0], "count": r[1]} for r in cur.fetchall()]
    total = sum(r["count"] for r in rows)

    return {
        "operation": "value_counts",
        "record_type": record_type,
        "column": column,
        "rows": rows,
        "total": total,
        "limit": limit,
    }


def relationships(
    cur: psycopg.Cursor,
    case_id: str,
    record_type: str,
    col_a: str,
    col_b: str,
    filters: Optional[List[Dict[str, str]]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """GROUP BY two columns — cross-tab of col_a vs col_b with counts."""
    valid_cols = set(get_columns_for_type(cur, case_id, record_type))
    for c in (col_a, col_b):
        if c not in valid_cols:
            raise ValueError(f"Invalid column: {c}")

    where, params = _build_where(case_id, record_type, filters, valid_cols)
    expr_a = _col_expr(col_a)
    expr_b = _col_expr(col_b)

    sql = (
        f"SELECT {expr_a}::text AS a, {expr_b}::text AS b, COUNT(*)::int AS count "
        f"FROM records WHERE {where} "
        f"GROUP BY 1, 2 ORDER BY count DESC LIMIT %s"
    )
    params.append(limit)
    cur.execute(sql, params)
    rows = [{"a": r[0], "b": r[1], "count": r[2]} for r in cur.fetchall()]

    unique_a = len({r["a"] for r in rows})
    unique_b = len({r["b"] for r in rows})

    return {
        "operation": "relationships",
        "record_type": record_type,
        "col_a": col_a,
        "col_b": col_b,
        "rows": rows,
        "unique_a": unique_a,
        "unique_b": unique_b,
        "total_pairs": len(rows),
        "limit": limit,
    }


def time_series(
    cur: psycopg.Cursor,
    case_id: str,
    record_type: str,
    interval: str = "hour",
    group_col: Optional[str] = None,
    filters: Optional[List[Dict[str, str]]] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """Bucket events by time interval, optionally grouped by a column."""
    if interval not in VALID_INTERVALS:
        raise ValueError(f"Invalid interval: {interval}")
    valid_cols = set(get_columns_for_type(cur, case_id, record_type))
    if group_col and group_col not in valid_cols:
        raise ValueError(f"Invalid column: {group_col}")

    where, params = _build_where(case_id, record_type, filters, valid_cols)

    if group_col:
        group_expr = _col_expr(group_col)
        sql = (
            f"SELECT date_trunc('{interval}', ts) AS bucket, "
            f"{group_expr}::text AS group_value, COUNT(*)::int AS count "
            f"FROM records WHERE {where} AND ts IS NOT NULL "
            f"GROUP BY 1, 2 ORDER BY 1, count DESC LIMIT %s"
        )
    else:
        sql = (
            f"SELECT date_trunc('{interval}', ts) AS bucket, "
            f"COUNT(*)::int AS count "
            f"FROM records WHERE {where} AND ts IS NOT NULL "
            f"GROUP BY 1 ORDER BY 1 LIMIT %s"
        )
    params.append(limit)
    cur.execute(sql, params)

    if group_col:
        rows = [
            {"bucket": r[0].isoformat() if r[0] else None, "group": r[1], "count": r[2]}
            for r in cur.fetchall()
        ]
    else:
        rows = [
            {"bucket": r[0].isoformat() if r[0] else None, "count": r[1]}
            for r in cur.fetchall()
        ]

    return {
        "operation": "time_series",
        "record_type": record_type,
        "interval": interval,
        "group_col": group_col,
        "rows": rows,
        "limit": limit,
    }


def top_n(
    cur: psycopg.Cursor,
    case_id: str,
    record_type: str,
    group_col: str,
    metric_col: Optional[str] = None,
    agg_func: str = "count",
    filters: Optional[List[Dict[str, str]]] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """Group by a column with aggregated metrics."""
    if agg_func not in VALID_AGG_FUNCS:
        raise ValueError(f"Invalid agg_func: {agg_func}")
    valid_cols = set(get_columns_for_type(cur, case_id, record_type))
    if group_col not in valid_cols:
        raise ValueError(f"Invalid column: {group_col}")
    if metric_col and metric_col not in valid_cols:
        raise ValueError(f"Invalid column: {metric_col}")

    where, params = _build_where(case_id, record_type, filters, valid_cols)
    group_expr = _col_expr(group_col)

    select_parts = [f"{group_expr}::text AS group_value", "COUNT(*)::int AS count"]
    if metric_col:
        metric_expr = _col_expr(metric_col)
        if agg_func == "count_distinct":
            select_parts.append(f"COUNT(DISTINCT {metric_expr})::int AS metric")
        else:
            select_parts.append(
                f"{agg_func.upper()}(({metric_expr})::numeric) AS metric"
            )

    select_clause = ", ".join(select_parts)
    sql = (
        f"SELECT {select_clause} FROM records WHERE {where} "
        f"GROUP BY 1 ORDER BY count DESC LIMIT %s"
    )
    params.append(limit)
    cur.execute(sql, params)

    if metric_col:
        rows = [
            {"group": r[0], "count": r[1], "metric": float(r[2]) if r[2] is not None else None}
            for r in cur.fetchall()
        ]
    else:
        rows = [{"group": r[0], "count": r[1]} for r in cur.fetchall()]

    return {
        "operation": "top_n",
        "record_type": record_type,
        "group_col": group_col,
        "metric_col": metric_col,
        "agg_func": agg_func,
        "rows": rows,
        "limit": limit,
    }


def correlate(
    cur: psycopg.Cursor,
    case_id: str,
    type_a: str,
    type_b: str,
    window_seconds: int = 300,
    entity_type: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Find events from two record types co-occurring within a time window.

    Optionally restrict to events sharing an entity (IP, hostname, etc.)
    via the entities table.
    """
    if window_seconds < 1 or window_seconds > 86400:
        raise ValueError("window_seconds must be 1–86400")

    params: list = [case_id, type_a, case_id, type_b, window_seconds]

    if entity_type:
        # Join through entities table: both records share an entity value
        sql = """
            SELECT
                r1.id AS id_a, r1.record_type AS type_a, r1.ts AS ts_a,
                r2.id AS id_b, r2.record_type AS type_b, r2.ts AS ts_b,
                e1.entity_type AS shared_entity_type,
                e1.value AS shared_entity_value,
                ABS(EXTRACT(EPOCH FROM r1.ts - r2.ts))::int AS delta_seconds
            FROM records r1
            JOIN entities e1 ON e1.record_id = r1.id AND e1.case_id = r1.case_id
            JOIN entities e2 ON e2.value = e1.value
                            AND e2.entity_type = e1.entity_type
                            AND e2.case_id = e1.case_id
            JOIN records r2 ON r2.id = e2.record_id
            WHERE r1.case_id = %s AND r1.record_type = %s
              AND r2.case_id = %s AND r2.record_type = %s
              AND r1.ts IS NOT NULL AND r2.ts IS NOT NULL
              AND ABS(EXTRACT(EPOCH FROM r1.ts - r2.ts)) <= %s
              AND e1.entity_type = %s
            ORDER BY delta_seconds, r1.ts
            LIMIT %s
        """
        params.append(entity_type)
    else:
        # Pure timestamp proximity — no entity join
        sql = """
            SELECT
                r1.id AS id_a, r1.record_type AS type_a, r1.ts AS ts_a,
                r2.id AS id_b, r2.record_type AS type_b, r2.ts AS ts_b,
                NULL AS shared_entity_type,
                NULL AS shared_entity_value,
                ABS(EXTRACT(EPOCH FROM r1.ts - r2.ts))::int AS delta_seconds
            FROM records r1
            JOIN records r2
              ON r2.case_id = r1.case_id
             AND r2.record_type = %s
             AND r2.ts IS NOT NULL
             AND ABS(EXTRACT(EPOCH FROM r1.ts - r2.ts)) <= %s
            WHERE r1.case_id = %s AND r1.record_type = %s
              AND r1.ts IS NOT NULL
            ORDER BY delta_seconds, r1.ts
            LIMIT %s
        """
        params = [type_b, window_seconds, case_id, type_a]

    params.append(limit)
    cur.execute(sql, params)

    rows = []
    for r in cur.fetchall():
        rows.append({
            "id_a": r[0],
            "type_a": r[1],
            "ts_a": r[2].isoformat() if r[2] else None,
            "id_b": r[3],
            "type_b": r[4],
            "ts_b": r[5].isoformat() if r[5] else None,
            "shared_entity_type": r[6],
            "shared_entity_value": r[7],
            "delta_seconds": r[8],
        })

    # Get available entity types for this case
    cur.execute(
        "SELECT DISTINCT entity_type FROM entities WHERE case_id = %s ORDER BY entity_type",
        (case_id,),
    )
    available_entity_types = [r[0] for r in cur.fetchall()]

    return {
        "operation": "correlate",
        "type_a": type_a,
        "type_b": type_b,
        "window_seconds": window_seconds,
        "entity_type": entity_type,
        "rows": rows,
        "total_pairs": len(rows),
        "available_entity_types": available_entity_types,
        "limit": limit,
    }