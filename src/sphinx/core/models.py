"""Sphinx Pydantic models — request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── Cases ──────────────────────────────────────────────

class CaseCreate(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=256)
    description: str = ""
    home_net: list[str] = []
    victim_ips: list[str] = []


class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    home_net: list[str] | None = None
    victim_ips: list[str] | None = None
    status: str | None = None


class CaseOut(BaseModel):
    id: str
    name: str
    description: str
    home_net: list[str]
    victim_ips: list[str]
    status: str
    created_at: datetime
    updated_at: datetime


# ── Users ──────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    role: str = "analyst"


class UserOut(BaseModel):
    id: str
    username: str
    role: str
    active: bool
    created_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Case Assignments ───────────────────────────────────

class CaseAssignment(BaseModel):
    user_id: str
    case_id: str


class CaseAssignmentOut(BaseModel):
    user_id: str
    case_id: str
    assigned_at: datetime


# ── Records ────────────────────────────────────────────

class RecordOut(BaseModel):
    id: int
    case_id: str
    record_type: str
    source_plugin: str
    raw: dict[str, Any]
    ts: datetime | None
    created_at: datetime


# ── Tasks ──────────────────────────────────────────────

class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1)
    description: str = ""


class TaskOut(BaseModel):
    id: int
    case_id: str
    title: str
    description: str
    status: str
    assigned_to: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


# ── Findings ───────────────────────────────────────────

class FindingOut(BaseModel):
    id: int
    case_id: str
    task_id: int | None
    title: str
    body: str
    severity: str
    evidence_ids: list[int]
    mitre_ids: list[str]
    created_at: datetime


# ── Dashboard ──────────────────────────────────────────

class DashboardSummary(BaseModel):
    case_id: str
    record_counts: dict[str, int]
    task_total: int
    task_done: int
    finding_count: int
    home_net: list[str]
    victim_ips: list[str]