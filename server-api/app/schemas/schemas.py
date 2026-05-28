# server-api/app/schemas/schemas.py
from __future__ import annotations
from datetime import datetime
from typing import Any, Literal
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
    enrollment_token: str = ""
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
    is_isolated: bool = False
    last_seen_at: datetime | None
    enrolled_at: datetime
    log_sources: list[LogSourceOut] = []
    model_config = {"from_attributes": True}

class HeartbeatRequest(BaseModel):
    agent_id: UUID
    status: str = "online"
    version: str | None = None
    buffer_dropped: int = 0

class AgentTaskDef(BaseModel):
    id: UUID
    task_type: str
    params: dict = {}

class HeartbeatResponse(BaseModel):
    config_hash: str
    log_sources: list[LogSourceOut]
    fim_paths: list[str] = []
    tasks: list[AgentTaskDef] = []

# ─── Ingest ──────────────────────────────────────────────────────

class LogIngestRequest(BaseModel):
    agent_id: UUID
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
    duplicate_count: int = 0
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
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

# ─── Platform Settings ───────────────────────────────────────────

class SettingOut(BaseModel):
    key: str
    value: str | None
    is_secret: bool
    description: str | None
    updated_at: datetime
    model_config = {"from_attributes": True}

class SettingUpdate(BaseModel):
    value: str

# ─── IT Hygiene ──────────────────────────────────────────────────

class HygieneSnapshotIn(BaseModel):
    agent_id: str
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    kernel: str | None = None
    arch: str | None = None
    uptime_seconds: int | None = None
    cpu_count: int | None = None
    mem_total_mb: int | None = None
    mem_used_mb: int | None = None
    disk_partitions: list[dict] | None = []
    open_ports: list[dict] | None = []
    users: list[dict] | None = []
    hygiene_score: int = 100
    issues: list[dict] | None = []
    packages: list[dict] | None = []
    collected_at: str | None = None

class HygieneSnapshotOut(BaseModel):
    id: str
    agent_id: str
    hostname: str | None
    group_id: str
    os_name: str | None
    os_version: str | None
    kernel: str | None
    arch: str | None
    uptime_seconds: int | None
    cpu_count: int | None
    mem_total_mb: int | None
    mem_used_mb: int | None
    disk_partitions: list[dict]
    open_ports: list[dict]
    users: list[dict]
    hygiene_score: int
    issues: list[dict]
    packages: list[dict]
    collected_at: datetime
    model_config = {"from_attributes": True}

# ─── UEBA ────────────────────────────────────────────────────────

class UebaEntityScoreListOut(BaseModel):
    """Lightweight schema for entity list — omits feature_profile to save bandwidth."""
    entity_type: str
    entity_value: str
    group_id: str
    risk_score: float
    anomaly_count: int
    last_anomaly_at: datetime | None
    last_seen_at: datetime | None
    updated_at: datetime
    model_config = {"from_attributes": True}

class UebaEntityScoreOut(UebaEntityScoreListOut):
    """Full schema for entity detail — includes feature_profile."""
    feature_profile: dict

class UebaAnomalyOut(BaseModel):
    id: UUID
    entity_type: str
    entity_value: str
    anomaly_score: float
    risk_score: float
    features: dict
    alert_id: UUID | None
    mitre_techniques: list[dict]
    ai_narrative: str | None
    ai_action: str | None
    case_id: UUID | None
    hash_ti_hits: list[dict]
    domain_ti_hits: list[dict]
    url_ti_hits: list[dict]
    ip_ti_hits: list[dict]
    powershell_hits: list[dict]
    command_hits: list[dict]
    detected_at: datetime
    model_config = {"from_attributes": True}

class UebaRiskHistoryPoint(BaseModel):
    snapshot_hour: datetime
    risk_score: float
    model_config = {"from_attributes": True}

class UebaEntityDetailOut(BaseModel):
    score: UebaEntityScoreOut
    anomalies: list[UebaAnomalyOut]

class UebaStatusOut(BaseModel):
    status: str
    trained_at: str | None
    user_snapshot_count: int
    ip_snapshot_count: int
    host_snapshot_count: int

# ─── Threat Hunts ────────────────────────────────────────────────

class ThreatHuntCreate(BaseModel):
    ioc_type: str   # ip, hostname, user, hash
    ioc_value: str
    alert_id: UUID | None = None  # if triggered from alert, auto-extract IoC

class ThreatHuntOut(BaseModel):
    id: UUID
    ioc_type: str
    ioc_value: str
    status: str
    group_id: str
    alert_count: int
    event_count: int
    fim_count: int
    risk_level: str | None
    timeline: list[Any] | None
    analysis: str | None
    related_alert_ids: list[str] | None
    created_at: datetime
    completed_at: datetime | None
    model_config = {"from_attributes": True}

# ─── FIM ─────────────────────────────────────────────────────────

class FimWatchPathOut(BaseModel):
    id: UUID
    path: str
    is_enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}

class FimWatchPathCreate(BaseModel):
    path: str

class FimEventItem(BaseModel):
    path: str
    event_type: str
    sha256: str | None = None
    size_bytes: int | None = None
    detected_at: str | None = None

class FimEventIn(BaseModel):
    agent_id: str
    events: list[FimEventItem]

class FimEventOut(BaseModel):
    id: UUID
    agent_id: UUID
    group_id: str
    path: str
    event_type: str
    sha256: str | None
    size_bytes: int | None
    detected_at: datetime
    model_config = {"from_attributes": True}

# ─── Agent Tasks ─────────────────────────────────────────────────

class AgentTaskCreate(BaseModel):
    agent_id: UUID | None = None
    task_type: str
    params: dict = {}

class AgentTaskOut(BaseModel):
    id: UUID
    agent_id: UUID | None
    fleet_hunt_id: UUID | None
    task_type: str
    params: dict
    status: str
    result: Any | None
    error: str | None
    created_at: datetime
    completed_at: datetime | None
    model_config = {"from_attributes": True}

class AgentTaskResultIn(BaseModel):
    status: str  # done | failed
    result: Any | None = None
    error: str | None = None

# ─── Fleet Hunt ──────────────────────────────────────────────────

class FleetHuntCreate(BaseModel):
    name: str
    description: str | None = None
    task_type: str
    params: dict = {}
    agent_ids: list[UUID] | None = None  # None = all online agents

class FleetHuntOut(BaseModel):
    id: UUID
    name: str
    description: str | None
    task_type: str
    params: dict
    status: str
    total_agents: int
    completed_agents: int
    group_id: str = "default"
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── Artifacts ───────────────────────────────────────────────────

class ArtifactCreate(BaseModel):
    name: str
    description: str | None = None
    task_type: str
    default_params: dict = {}

class ArtifactOut(BaseModel):
    id: UUID
    name: str
    description: str | None
    task_type: str
    default_params: dict
    is_enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}

class ArtifactRunRequest(BaseModel):
    agent_ids: list[UUID] | None = None  # None = fleet
    params: dict | None = None  # override default_params

# ─── YARA Rules ──────────────────────────────────────────────────

class YaraRuleCreate(BaseModel):
    name: str
    description: str | None = None
    content: str

class YaraRuleOut(BaseModel):
    id: UUID
    name: str
    description: str | None
    content: str
    is_enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}

class YaraScanRequest(BaseModel):
    agent_id: UUID
    path: str
    recursive: bool = False
    rule_ids: list[UUID] | None = None  # None = all enabled rules

# ─── Enrollment Tokens ───────────────────────────────────────────

class EnrollmentTokenCreate(BaseModel):
    label: str = ""
    group_id: str = "default"
    expires_hours: int = 24  # 0 = never expires

class EnrollmentTokenOut(BaseModel):
    id: UUID
    label: str
    group_id: str
    expires_at: datetime | None
    is_active: bool
    used_at: datetime | None
    used_by_agent_id: UUID | None
    created_at: datetime
    model_config = {"from_attributes": True}

class EnrollmentTokenCreated(EnrollmentTokenOut):
    token: str  # raw value — shown only on creation

# ─── Correlation Rules ────────────────────────────────────────────

class CorrelationRuleCreate(BaseModel):
    title: str
    description: str | None = None
    match_field: Literal["source_ip", "hostname", "group_id"] = "source_ip"
    min_count: int = 5
    timewindow: int = 300
    severity_filter: str | None = None
    output_severity: str = "high"
    output_title: str
    is_enabled: bool = True
    group_id: str | None = None

class CorrelationRuleUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    match_field: Literal["source_ip", "hostname", "group_id"] | None = None
    min_count: int | None = None
    timewindow: int | None = None
    severity_filter: str | None = None
    output_severity: str | None = None
    output_title: str | None = None
    is_enabled: bool | None = None
    group_id: str | None = None

class CorrelationRuleOut(BaseModel):
    id: UUID
    title: str
    description: str | None
    match_field: str
    min_count: int
    timewindow: int
    severity_filter: str | None
    output_severity: str
    output_title: str
    is_enabled: bool
    group_id: str | None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

# ─── Audit Logs ──────────────────────────────────────────────────

class AuditLogOut(BaseModel):
    id: UUID
    actor_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    detail: dict[str, Any]
    created_at: datetime
    model_config = {"from_attributes": True}
