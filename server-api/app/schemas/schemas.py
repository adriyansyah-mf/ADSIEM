# server-api/app/schemas/schemas.py
from __future__ import annotations
from datetime import date, datetime, timezone
import hashlib
import json
import re
from typing import Annotated, Any, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field, field_validator, model_validator

# ─── Auth ────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: Optional[bool] = None

class UserMe(BaseModel):
    id: UUID
    username: str
    email: str
    role: str
    group_id: str
    mfa_enabled: bool = False
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
    role: str
    group_id: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}

    @field_validator("role", mode="before")
    @classmethod
    def extract_role_name(cls, v: object) -> str:
        return v.name if hasattr(v, "name") else str(v)

# ─── Agents ──────────────────────────────────────────────────────

class LogSourceIn(BaseModel):
    path: str
    log_type: str
    is_enabled: bool = True

class FirewallRuleIn(BaseModel):
    action: Literal["block", "allow"] = "block"
    cidr: str
    proto: Literal["any", "tcp", "udp", "icmp"] = "any"
    port: int = Field(0, ge=0, le=65535)
    direction: Literal["inbound", "outbound", "both"] = "both"
    ttl_seconds: int = Field(0, ge=0, le=2592000)
    reason: str = ""
    is_enabled: bool = True

    @field_validator("cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid cidr: {v}") from exc
        return v

    @model_validator(mode="after")
    def _port_needs_proto(self):
        if self.port and self.proto not in ("tcp", "udp"):
            raise ValueError("port requires proto tcp or udp")
        return self

class FirewallRuleOut(BaseModel):
    id: UUID
    agent_id: UUID
    action: str
    cidr: str
    proto: str
    port: int
    direction: str
    ttl_seconds: int
    reason: str
    is_enabled: bool
    created_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)

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
    approved: bool = True
    is_isolated: bool = False
    last_seen_at: datetime | None
    flow_poll_at: datetime | None = None
    enrolled_at: datetime
    log_sources: list[LogSourceOut] = []
    # read from the agent row for the summary below; the full snapshot is
    # served by GET /api/agents/{id}/evidence
    evidence_health: dict | None = Field(default=None, exclude=True)
    evidence_health_at: datetime | None = Field(default=None, exclude=True)
    model_config = {"from_attributes": True}

    @computed_field
    @property
    def evidence(self) -> dict:
        """Durable evidence delivery summary: status, reason, reported_at, stale."""
        from app.services.evidence_status import evidence_status
        return evidence_status(self.evidence_health, self.evidence_health_at, datetime.now(timezone.utc))

# ─── Evidence health (durable agents) ────────────────────────────
# What agent/internal/evidence Health + Sender.Status send in the heartbeat.
# Bounded and enumerated: it is stored and shown, never used as a metric label.

_MAX_COUNT = (1 << 63) - 1
EvidenceCount = Annotated[int, Field(ge=0, le=_MAX_COUNT)]
EvidenceLossReason = Literal["capacity", "oversize", "source_failure", "storage_failure", "rotation_gap", "legacy_import"]


class EvidenceSourceHealth(BaseModel):
    model_config = ConfigDict(extra="ignore")
    state: Literal["healthy", "degraded", "paused", "unavailable"]
    reason: str = Field(default="", max_length=256)
    updated_at: datetime | None = None


class EvidenceSenderStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")
    state: Literal["idle", "sending", "retrying", "blocked"]
    reason: str = Field(default="", max_length=64)
    since: datetime | None = None
    failures: int = Field(default=0, ge=0, le=1 << 31)


class EvidenceHealth(BaseModel):
    """Cumulative journal health: counters persist across restarts and failed heartbeats."""
    model_config = ConfigDict(extra="ignore")  # newer agents may add fields
    version: Literal[1]
    mode: Literal["durable"] = "durable"
    state: Literal["healthy", "degraded"]
    reason: Literal["", "source_failure", "held", "quarantined", "storage_failure", "capacity",
                    "journal_unavailable"] = ""
    queued_events: EvidenceCount = 0
    queued_bytes: EvidenceCount = 0
    oldest_queued_at: datetime | None = None
    last_receipt_at: datetime | None = None
    retries: EvidenceCount = 0
    quarantined: EvidenceCount = 0
    held: EvidenceCount = 0
    unknown_gaps: EvidenceCount = 0
    known_loss: dict[EvidenceLossReason, EvidenceCount] = Field(default_factory=dict)
    pending_loss: dict[EvidenceLossReason, EvidenceCount] = Field(default_factory=dict)
    loss_uncertain: bool = False
    sources: dict[Annotated[str, Field(max_length=512)], EvidenceSourceHealth] = Field(
        default_factory=dict, max_length=256)
    sender: EvidenceSenderStatus | None = None

    @field_validator("known_loss", "pending_loss", "sources", mode="before")
    @classmethod
    def null_map_is_empty(cls, value):
        return {} if value is None else value  # Go encodes an empty nil map as null


class HeartbeatRequest(BaseModel):
    agent_id: UUID
    status: str = "online"
    version: str | None = None
    buffer_dropped: int = 0
    reason: str | None = None          # with status "stopping": service_stop | system_shutdown
    integrity: dict[str, str] | None = None  # binary_sha256 / config_sha256, agents >= 1.7.0
    session: str | None = None  # one per agent process, with a rising seq (agents >= 1.8.0)
    seq: int | None = None
    evidence_health: EvidenceHealth | None = None  # durable agents only

    @field_validator("evidence_health", mode="wrap")
    @classmethod
    def drop_invalid_evidence_health(cls, value, handler):
        # An invalid or unbounded health object is rejected on its own: the
        # heartbeat still carries tasks and config, so it must not fail.
        try:
            return handler(value)
        except ValueError:
            return None

class AgentTaskDef(BaseModel):
    id: UUID
    task_type: str
    params: dict = {}

class HeartbeatResponse(BaseModel):
    config_hash: str
    evidence_protocols: list[int] = Field(default_factory=list)
    evidence_batch_max: int = 0  # >0: POST /api/ingest/v2/logs takes up to this many events
    log_sources: list[LogSourceOut]
    fim_paths: list[str] = []
    tasks: list[AgentTaskDef] = []
    firewall: list[dict] = []
    uninstall_token_sha256: str = ""  # agents >= 1.8.0 refuse removal without the token

# ─── Ingest ──────────────────────────────────────────────────────

def _evidence_timestamp(value: str, *, utc: bool = False) -> str:
    # datetime stores microseconds; parse whole seconds separately so the immutable
    # nanosecond fraction survives both normalization and PostgreSQL round trips.
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
        value,
    )
    if match is None:
        raise ValueError("collected_at must be RFC3339 with at most nanosecond precision")
    seconds, fraction, offset = match.groups()
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise ValueError("invalid timestamp offset")
    parsed = datetime.fromisoformat(seconds + offset.replace("Z", "+00:00"))
    if utc:
        parsed = parsed.astimezone(timezone.utc)
        seconds = f"{parsed.year:04}-{parsed.month:02}-{parsed.day:02}T{parsed.hour:02}:{parsed.minute:02}:{parsed.second:02}"
        offset = "Z"
    if offset in {"+00:00", "-00:00"}:
        offset = "Z"
    fraction = (fraction or "").rstrip("0")
    return seconds + ("." + fraction if fraction else "") + offset


class EvidenceCursor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source: str
    generation: str
    identity: str
    offset: int = Field(default=0, ge=-(1 << 63), lt=1 << 63, strict=True)
    bookmark: str = ""
    empty: bool = Field(default=False, strict=True)

    @field_validator("source", "generation", "identity", "bookmark")
    @classmethod
    def valid_unicode(cls, value: str) -> str:
        value.encode("utf-8")
        return value


class EvidenceEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    protocol_version: Literal[2]
    event_id: UUID
    agent_id: UUID
    collected_at: str
    hostname: str
    log_type: str
    location: str
    raw_message: str
    cursor: EvidenceCursor | None = None
    legacy_import: bool = Field(default=False, strict=True)

    @field_validator("event_id", "agent_id")
    @classmethod
    def nonzero_uuid(cls, value: UUID) -> UUID:
        if value.int == 0:
            raise ValueError("evidence identity must be a nonzero UUID")
        return value

    @field_validator("protocol_version", mode="before")
    @classmethod
    def integer_protocol(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError("protocol_version must be an integer")
        return value

    @field_validator("collected_at")
    @classmethod
    def valid_timestamp(cls, value: str) -> str:
        try:
            _evidence_timestamp(value, utc=True)
        except OverflowError as exc:
            raise ValueError("collected_at is outside the UTC timestamp range") from exc
        return _evidence_timestamp(value)

    @field_validator("hostname", "log_type", "location", "raw_message")
    @classmethod
    def valid_unicode(cls, value: str) -> str:
        value.encode("utf-8")
        return value

    def canonical_json(self) -> str:
        payload = self.model_dump(mode="json", exclude_defaults=True)
        payload["collected_at"] = _evidence_timestamp(self.collected_at, utc=True)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    @property
    def encoded_size(self) -> int:
        # encoding/json uses compact UTF-8, escapes HTML and Unicode separators,
        # and omits the zero-valued optional fields in the Go envelope/cursor.
        encoded = json.dumps(self.model_dump(mode="json", exclude_defaults=True),
                             ensure_ascii=False, separators=(",", ":"))
        for character in "<>&\u2028\u2029":
            encoded = encoded.replace(character, f"\\u{ord(character):04x}")
        return len(encoded.encode("utf-8"))


class EvidenceReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)
    protocol_version: Literal[2] = 2
    event_id: UUID
    status: Literal["accepted", "duplicate"]
    receipt_id: UUID


class LogIngestRequest(BaseModel):
    agent_id: UUID
    log_type: str
    raw_message: str
    received_at: datetime
    hostname: str
    location: str | None = Field(default=None, max_length=1024)  # source file (agent >= 1.4)

    @field_validator("log_type", "raw_message")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v

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
    source: str = "custom"
    external_id: str | None = None
    sigma_status: str | None = None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class RuleListItem(RuleOut):
    logsource: dict[str, Any] = {}
    collected: bool = True             # some log source on this platform can feed the rule
    modified_locally: bool = False     # imported rule edited since its last import

class RuleTestRequest(BaseModel):
    content: str
    sample_event: dict[str, Any]

class RuleTestResponse(BaseModel):
    matched: bool
    rule_title: str | None = None
    error: str | None = None
    logsource_applies: bool | None = None  # only known when sample_event has a log_type

class SigmaHQImportRequest(BaseModel):
    ruleset: str = "core"                  # core, core+, core++, emerging_threats, all
    release: str = "latest"                # a SigmaHQ release tag such as r2026-07-01
    enable_levels: list[str] = ["high", "critical"]
    enable_statuses: list[str] = ["stable", "test"]

class SigmaHQImportResult(BaseModel):
    release: str
    total: int
    created: int
    updated: int
    unchanged: int
    kept_local_edits: int
    rejected: int
    enabled: int
    not_collected: int
    rejected_examples: list[str] = []

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
    source_ip_country: str | None = None
    hostname: str | None
    assignee_id: UUID | None
    duplicate_count: int = 0
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    ai_verdict: str | None = None
    mitre_techniques: list = []
    kill_chain_stage: str | None = None
    context: dict = {}
    created_at: datetime
    updated_at: datetime
    notes: list[AlertNoteOut] = []
    model_config = {"from_attributes": True}

class AlertRuleInfo(BaseModel):
    id: UUID
    title: str
    description: str | None
    level: str
    tags: list[str] = []
    content: str

class AlertAgentInfo(BaseModel):
    id: UUID
    hostname: str
    name: str
    version: str | None
    status: str
    last_seen_at: datetime | None

class AlertRelatedOut(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    source_ip: str | None
    hostname: str | None
    duplicate_count: int = 0
    created_at: datetime
    model_config = {"from_attributes": True}

class AlertUebaInfo(BaseModel):
    entity_type: str
    entity_value: str
    risk_score: float
    anomaly_score: float
    reasons: list[dict] = []
    mitre_techniques: list[dict] = []
    features: dict = {}
    ai_action: str | None = None
    ai_narrative: str | None = None
    model_config = {"from_attributes": True}

class AlertDetailOut(AlertOut):
    rule: AlertRuleInfo | None = None
    rule_fired_24h: int = 0  # occurrences of the same rule in the last 24h, duplicates included
    agent: AlertAgentInfo | None = None
    ueba: AlertUebaInfo | None = None
    mitre: list[dict] = []   # [{id, name, tactic, url}]
    event: dict | None = None  # the triggering log document (full_log, location, decoder, decoded fields)
    related: list[AlertRelatedOut] = []

# ─── AI feedback (analyst rating of an AI triage verdict) ────────

class AiFeedbackCreate(BaseModel):
    rating: Literal["correct", "incorrect"]
    correct_verdict: str | None = None
    note: str | None = None

class AiFeedbackOut(BaseModel):
    id: UUID
    entity_type: str
    entity_id: UUID
    ai_verdict: str | None
    rating: str
    correct_verdict: str | None
    note: str | None
    created_at: datetime
    model_config = {"from_attributes": True}

class AlertSourceLogOut(BaseModel):
    event: EventOut | None
    raw_log: RawLogOut | None

# ─── Webhooks ────────────────────────────────────────────────────

class WebhookCreate(BaseModel):
    name: str
    url: str
    is_enabled: bool = True
    group_id: str | None = None
    payload_format: str = "default"

class WebhookUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    is_enabled: bool | None = None
    group_id: str | None = None
    payload_format: str | None = None

class WebhookOut(BaseModel):
    id: UUID
    name: str
    url: str
    is_enabled: bool
    group_id: str | None
    payload_format: str
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
    ai_confidence: float | None
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
    # Cursor for the next page when the source is Elasticsearch (search_after-based —
    # ES's offset pagination hard-fails past 10,000 results, which real log/event
    # volume blows through quickly). None once there are no more pages. Postgres-backed
    # endpoints leave this unset and keep using page/page_size as before.
    next_after: str | None = None

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
    reasons: list[dict] = []
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

# ─── Reports ──────────────────────────────────────────────────────

class ReportGenerateRequest(BaseModel):
    date_from: date
    date_to: date
    language: str = "English"

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

# ─── SOP Documents ───────────────────────────────────────────────

class SopDocumentOut(BaseModel):
    id: UUID
    group_id: str
    filename: str
    content_type: str
    status: str
    uploaded_by: UUID | None
    created_at: datetime
    model_config = {"from_attributes": True}

# ─── SOC Assistant (read-only chat) ──────────────────────────────

class AssistantChatMessage(BaseModel):
    role: str
    content: str

class AssistantChatRequest(BaseModel):
    message: str
    history: list[AssistantChatMessage] = []

class AssistantChatResponse(BaseModel):
    reply: str
    tools_used: list[str]
    actions: list[dict] = []

# ─── Live response flows ─────────────────────────────────────────

class FlowArtifactIn(BaseModel):
    content: str = Field(max_length=100_000)

class FlowCreate(BaseModel):
    agent_id: UUID
    artifact: str
    params: dict[str, Any] = {}
    timeout: int | None = None
    max_rows: int | None = None

class FlowOut(BaseModel):
    id: UUID
    agent_id: UUID
    artifact: str
    params: dict
    status: str
    total_rows: int
    error: str | None
    timeout: int
    max_rows: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    model_config = {"from_attributes": True}

class FlowSourceCount(BaseModel):
    name: str
    rows: int

class FlowDetailOut(FlowOut):
    request: dict
    artifact_content: str
    sources: list[FlowSourceCount] = []

class FlowLogOut(BaseModel):
    ts: datetime
    level: str
    message: str
    model_config = {"from_attributes": True}

class FlowResultsOut(BaseModel):
    source: str
    columns: list[str]
    rows: list[dict]
    total: int

class AgentFlowLogIn(BaseModel):
    level: Literal["debug", "info", "warn", "error"] = "info"
    message: str = Field(max_length=4000)

class AgentFlowUpdate(BaseModel):
    state: Literal["running", "finished", "error", "cancelled"] | None = None
    source: str | None = None
    rows: list[dict[str, Any]] = Field(default=[], max_length=1000)
    logs: list[AgentFlowLogIn] = Field(default=[], max_length=200)
    error: str | None = Field(default=None, max_length=4000)
