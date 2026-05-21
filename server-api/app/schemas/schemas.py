# server-api/app/schemas/schemas.py
from __future__ import annotations
from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field

# ─── Auth ────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserMe(BaseModel):
    id: UUID
    username: str
    email: str
    role: str
    group_id: str
    model_config = {"from_attributes": True}

# ─── Users ───────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role_id: int
    group_id: str = "default"

class UserUpdate(BaseModel):
    username: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    role_id: int | None = None
    group_id: str | None = None
    is_active: bool | None = None

class UserOut(BaseModel):
    id: UUID
    username: str
    email: str
    role_id: int
    group_id: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── Agents ──────────────────────────────────────────────────────

class LogSourceIn(BaseModel):
    path: str
    log_type: str
    is_enabled: bool = True

class EnrollRequest(BaseModel):
    enrollment_token: str
    hostname: str
    version: str
    group: str = "default"
    name: str
    log_sources: list[LogSourceIn] = []

class EnrollResponse(BaseModel):
    agent_id: UUID
    agent_token: str

class AgentUpdate(BaseModel):
    name: str | None = None
    group_id: str | None = None

class LogSourceOut(BaseModel):
    id: UUID
    path: str
    log_type: str
    is_enabled: bool
    model_config = {"from_attributes": True}

class AgentOut(BaseModel):
    id: UUID
    name: str
    hostname: str
    group_id: str
    version: str | None
    status: str
    last_seen_at: datetime | None
    enrolled_at: datetime
    log_sources: list[LogSourceOut] = []
    model_config = {"from_attributes": True}

class HeartbeatRequest(BaseModel):
    agent_id: UUID
    status: str = "online"
    version: str | None = None
    buffer_dropped: int = 0

class HeartbeatResponse(BaseModel):
    config_hash: str
    log_sources: list[LogSourceOut]

# ─── Ingest ──────────────────────────────────────────────────────

class LogIngestRequest(BaseModel):
    agent_id: UUID
    agent_token: str
    log_type: str
    raw_message: str
    received_at: datetime
    hostname: str

# ─── Logs & Events ───────────────────────────────────────────────

class RawLogOut(BaseModel):
    id: UUID
    agent_id: UUID | None
    log_type: str | None
    raw_message: str
    received_at: datetime
    model_config = {"from_attributes": True}

class EventOut(BaseModel):
    id: UUID
    agent_id: UUID | None
    group_id: str
    decoded_fields: dict[str, Any]
    event_category: str | None
    event_action: str | None
    source_ip: str | None
    user_name: str | None
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── Rules ───────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    title: str
    description: str | None = None
    content: str
    level: str = "medium"
    tags: list[str] = []
    mitre_tags: list[str] = []
    is_enabled: bool = True
    group_id: str | None = None

class RuleUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    content: str | None = None
    level: str | None = None
    tags: list[str] | None = None
    mitre_tags: list[str] | None = None
    is_enabled: bool | None = None
    group_id: str | None = None

class RuleOut(BaseModel):
    id: UUID
    title: str
    description: str | None
    content: str
    level: str
    tags: list[str]
    mitre_tags: list[str]
    version: int
    is_enabled: bool
    group_id: str | None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class RuleTestRequest(BaseModel):
    content: str
    sample_event: dict[str, Any]

class RuleTestResponse(BaseModel):
    matched: bool
    rule_title: str | None = None
    error: str | None = None

# ─── Decoders ────────────────────────────────────────────────────

class DecoderCreate(BaseModel):
    name: str
    log_type: str
    content: str
    priority: int = 100
    is_enabled: bool = True

class DecoderUpdate(BaseModel):
    name: str | None = None
    log_type: str | None = None
    content: str | None = None
    priority: int | None = None
    is_enabled: bool | None = None

class DecoderOut(BaseModel):
    id: UUID
    name: str
    log_type: str
    content: str
    priority: int
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class DecoderTestRequest(BaseModel):
    content: str
    raw_message: str

class DecoderTestResponse(BaseModel):
    matched: bool
    decoded_fields: dict[str, Any] = {}
    error: str | None = None

# ─── Alerts ──────────────────────────────────────────────────────

class AlertUpdate(BaseModel):
    status: str | None = None
    assignee_id: UUID | None = None

class AlertNoteCreate(BaseModel):
    content: str

class AlertNoteOut(BaseModel):
    id: UUID
    author_id: UUID | None
    content: str
    created_at: datetime
    model_config = {"from_attributes": True}

class AlertOut(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    rule_id: UUID | None
    event_id: UUID | None
    agent_id: UUID | None
    group_id: str
    source_ip: str | None
    hostname: str | None
    assignee_id: UUID | None
    created_at: datetime
    updated_at: datetime
    notes: list[AlertNoteOut] = []
    model_config = {"from_attributes": True}

# ─── Webhooks ────────────────────────────────────────────────────

class WebhookCreate(BaseModel):
    name: str
    url: str
    is_enabled: bool = True
    group_id: str | None = None

class WebhookUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    is_enabled: bool | None = None
    group_id: str | None = None

class WebhookOut(BaseModel):
    id: UUID
    name: str
    url: str
    is_enabled: bool
    group_id: str | None
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── Cases ───────────────────────────────────────────────────────

class CaseNoteOut(BaseModel):
    id: UUID
    case_id: UUID
    author_id: UUID | None
    content: str
    is_ai_generated: bool
    created_at: datetime
    model_config = {"from_attributes": True}

class CaseNoteCreate(BaseModel):
    content: str

class CaseOut(BaseModel):
    id: UUID
    title: str
    description: str | None
    severity: str
    status: str
    alert_id: UUID | None
    assignee_id: UUID | None
    ai_reasoning: str | None
    ioc_data: dict
    search_intel: dict
    created_by_ai: bool
    escalated_at: datetime | None
    group_id: str
    created_at: datetime
    updated_at: datetime
    notes: list[CaseNoteOut] = []
    model_config = {"from_attributes": True}

class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    severity: str = "medium"
    alert_id: UUID | None = None

class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    assignee_id: UUID | None = None

# ─── Pagination ──────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[Any]
