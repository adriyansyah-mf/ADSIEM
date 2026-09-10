# server-api/app/models/models.py
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer,
    String, Text, ARRAY, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.core.database import Base

def now_utc():
    return datetime.now(timezone.utc)

class Role(Base):
    __tablename__ = "roles"
    id         = Column(Integer, primary_key=True)
    name       = Column(String(50), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")
    users       = relationship("User", back_populates="role")

class Permission(Base):
    __tablename__ = "permissions"
    id         = Column(Integer, primary_key=True)
    name       = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    roles      = relationship("Role", secondary="role_permissions", back_populates="permissions")

class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id       = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

class User(Base):
    __tablename__ = "users"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username      = Column(String(100), unique=True, nullable=False)
    email         = Column(String(255), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    role_id       = Column(Integer, ForeignKey("roles.id"), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default")
    is_active     = Column(Boolean, nullable=False, default=True)
    mfa_secret    = Column(Text, nullable=True)
    mfa_enabled   = Column(Boolean, nullable=False, server_default='false')
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    updated_at    = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    role          = relationship("Role", back_populates="users")

class Agent(Base):
    __tablename__ = "agents"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name         = Column(String(255), nullable=False)
    hostname     = Column(String(255), nullable=False)
    group_id     = Column(String(100), nullable=False, default="default")
    token_hash   = Column(Text, nullable=False)
    version      = Column(String(50))
    status       = Column(String(20), nullable=False, default="offline")
    is_isolated  = Column(Boolean, nullable=False, default=False)
    last_seen_at = Column(DateTime(timezone=True))
    enrolled_at  = Column(DateTime(timezone=True), default=now_utc)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    # Fleet-health telemetry (AGENT_PRODUCTION_IMPROVEMENT_ROADMAP.md P0-B)
    buffer_depth = Column(Integer, nullable=True)
    buffer_dropped_total = Column(BigInteger, nullable=False, default=0)
    oldest_buffered_event_age_seconds = Column(Integer, nullable=True)
    uptime_seconds = Column(Integer, nullable=True)
    log_sources  = relationship("AgentLogSource", back_populates="agent", cascade="all, delete-orphan")

class AgentLogSource(Base):
    __tablename__ = "agent_log_sources"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id   = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    path       = Column(Text, nullable=False)
    log_type   = Column(String(100), nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    agent      = relationship("Agent", back_populates="log_sources")

class Rule(Base):
    __tablename__ = "rules"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title       = Column(String(255), nullable=False)
    description = Column(Text)
    content     = Column(Text, nullable=False)
    level       = Column(String(20), nullable=False, default="medium")
    tags        = Column(ARRAY(Text), nullable=False, default=list)
    mitre_tags  = Column(ARRAY(Text), nullable=False, default=list)
    version     = Column(Integer, nullable=False, default=1)
    is_enabled  = Column(Boolean, nullable=False, default=True)
    group_id    = Column(String(100))
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class RuleRevision(Base):
    __tablename__ = "rule_revisions"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id     = Column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="CASCADE"), nullable=False)
    version     = Column(Integer, nullable=False)
    content     = Column(Text, nullable=False)
    created_by  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at  = Column(DateTime(timezone=True), default=now_utc)

class Decoder(Base):
    __tablename__ = "decoders"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name       = Column(String(255), unique=True, nullable=False)
    log_type   = Column(String(100), nullable=False)
    content    = Column(Text, nullable=False)
    priority   = Column(Integer, nullable=False, default=100)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class Alert(Base):
    __tablename__ = "alerts"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title            = Column(String(255), nullable=False)
    severity         = Column(String(20), nullable=False, default="medium")
    status           = Column(String(30), nullable=False, default="new")
    rule_id          = Column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"))
    correlation_id   = Column(String(255))
    correlation_key  = Column(String(512))
    source_event_ids = Column(JSONB, nullable=False, default=list)
    event_id         = Column(UUID(as_uuid=True))  # pointer into Elasticsearch `logs` index _id, no FK (events live in ES now)
    agent_id         = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id         = Column(String(100), nullable=False, default="default")
    source_ip        = Column(String(45))
    hostname         = Column(String(255))
    assignee_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    duplicate_count  = Column(Integer, nullable=False, default=0)
    acknowledged_at  = Column(DateTime(timezone=True))
    resolved_at      = Column(DateTime(timezone=True))
    mitre_techniques = Column(JSONB, nullable=False, default=list)
    kill_chain_stage = Column(String(50))
    ai_verdict       = Column(String(50))  # escalate/create_case/monitor/false_positive from AI L1 triage
    created_at       = Column(DateTime(timezone=True), default=now_utc)
    updated_at       = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    notes            = relationship("AlertNote", back_populates="alert", cascade="all, delete-orphan")

class AlertNote(Base):
    __tablename__ = "alert_notes"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id   = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    author_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    content    = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    alert      = relationship("Alert", back_populates="notes")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_type    = Column(String(20), nullable=False, default="user")
    actor_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    group_id      = Column(String(100), nullable=True)
    action        = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id   = Column(Text)
    detail        = Column(JSONB, nullable=False, default=dict)
    request_id    = Column(String(64), nullable=True)
    payload_hash  = Column(String(64), nullable=True)
    previous_hash = Column(String(64), nullable=True)
    chain_hash    = Column(String(64), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=now_utc)

class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"
    group_id   = Column(String(100), primary_key=True)
    chain_hash = Column(String(64), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class WebhookConfig(Base):
    __tablename__ = "webhook_configs"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name           = Column(String(255), nullable=False)
    url            = Column(Text, nullable=False)
    is_enabled     = Column(Boolean, nullable=False, default=True)
    group_id       = Column(String(100))
    payload_format = Column(String(50), nullable=False, server_default='default')
    created_at     = Column(DateTime(timezone=True), default=now_utc)
    updated_at     = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class PlatformSetting(Base):
    __tablename__ = "platform_settings"
    key         = Column(String(100), primary_key=True)
    value       = Column(Text)
    is_secret   = Column(Boolean, nullable=False, default=False)
    description = Column(Text)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    updated_by  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

class SituationBriefCache(Base):
    """One row per group (or "global" for the unscoped/superadmin view) —
    Command Center's AI Situation Brief regenerates at most once per TTL
    window (see situation_brief.py) instead of on every page load/poll."""
    __tablename__ = "situation_brief_cache"
    group_key        = Column(String(100), primary_key=True)
    status           = Column(String(20), nullable=False)
    brief            = Column(Text, nullable=True)
    cited_alert_ids  = Column(JSONB, nullable=False, default=list)
    generated_at     = Column(DateTime(timezone=True), nullable=False)

class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id          = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    webhook_config_id = Column(UUID(as_uuid=True), ForeignKey("webhook_configs.id", ondelete="CASCADE"), nullable=False)
    group_id          = Column(String(100), nullable=True)
    payload           = Column(JSONB, nullable=False, default=dict)
    status            = Column(String(20), nullable=False, default="pending")
    attempts          = Column(Integer, nullable=False, default=0)
    last_error        = Column(Text, nullable=True)
    error_class       = Column(String(100), nullable=True)
    first_failed_at   = Column(DateTime(timezone=True), nullable=True)
    last_attempted_at = Column(DateTime(timezone=True))
    created_at        = Column(DateTime(timezone=True), default=now_utc)
    updated_at        = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class Case(Base):
    __tablename__ = "cases"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title         = Column(String(255), nullable=False)
    description   = Column(Text)
    severity      = Column(String(20), nullable=False, default="medium")
    status        = Column(String(30), nullable=False, default="open")  # open/in_review/escalated/resolved/closed
    alert_id      = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    assignee_id   = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ai_reasoning  = Column(Text)
    ai_confidence = Column(Float)
    ioc_data      = Column(JSONB, nullable=False, default=dict)
    search_intel  = Column(JSONB, nullable=False, default=dict)
    created_by_ai = Column(Boolean, nullable=False, default=False)
    escalated_at  = Column(DateTime(timezone=True))
    group_id      = Column(String(100), nullable=False, default="default")
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    updated_at    = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    notes         = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")

class HygieneSnapshot(Base):
    __tablename__ = "hygiene_snapshots"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id        = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    hostname        = Column(String(255))
    group_id        = Column(String(100), nullable=False, default="default")
    os_name         = Column(String(100))
    os_version      = Column(String(100))
    kernel          = Column(String(100))
    arch            = Column(String(20))
    uptime_seconds  = Column(Integer)
    cpu_count       = Column(Integer)
    mem_total_mb    = Column(Integer)
    mem_used_mb     = Column(Integer)
    disk_partitions = Column(JSONB, nullable=False, default=list)
    open_ports      = Column(JSONB, nullable=False, default=list)
    users           = Column(JSONB, nullable=False, default=list)
    hygiene_score   = Column(Integer, nullable=False, default=100)
    issues          = Column(JSONB, nullable=False, default=list)
    packages        = Column(JSONB, nullable=False, default=list)
    hardening_checks = Column(JSONB, nullable=False, default=list)
    collected_at    = Column(DateTime(timezone=True), default=now_utc)

class CaseNote(Base):
    __tablename__ = "case_notes"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id         = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    author_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    content         = Column(Text, nullable=False)
    is_ai_generated = Column(Boolean, nullable=False, default=False)
    created_at      = Column(DateTime(timezone=True), default=now_utc)
    case            = relationship("Case", back_populates="notes")

class UebaFeatureSnapshot(Base):
    __tablename__ = "ueba_feature_snapshots"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type   = Column(String(20),  nullable=False)
    entity_value  = Column(String(255), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default")
    features      = Column(JSONB,       nullable=False, default=dict)
    risk_score    = Column(Float,       nullable=False, default=0.0)
    snapshot_hour = Column(DateTime(timezone=True), nullable=False)
    created_at    = Column(DateTime(timezone=True), default=now_utc)

class UebaEntityScore(Base):
    __tablename__ = "ueba_entity_scores"
    entity_type     = Column(String(20),  primary_key=True)
    entity_value    = Column(String(255), primary_key=True)
    group_id        = Column(String(100), nullable=False, default="default")
    risk_score      = Column(Float,       nullable=False, default=0.0)
    anomaly_count   = Column(Integer,     nullable=False, default=0)
    last_anomaly_at = Column(DateTime(timezone=True))
    last_seen_at    = Column(DateTime(timezone=True))
    updated_at      = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    feature_profile = Column(JSONB,                   nullable=False, default=dict)

class UebaAnomaly(Base):
    __tablename__ = "ueba_anomalies"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type   = Column(String(20),  nullable=False)
    entity_value  = Column(String(255), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default")
    anomaly_score = Column(Float,       nullable=False)
    risk_score    = Column(Float,       nullable=False)
    features      = Column(JSONB,       nullable=False, default=dict)
    alert_id         = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"))
    mitre_techniques = Column(JSONB,               nullable=False, default=list)
    ai_narrative     = Column(Text)
    ai_action        = Column(String(20))
    case_id          = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="SET NULL"))
    hash_ti_hits     = Column(JSONB,               nullable=False, default=list)
    domain_ti_hits   = Column(JSONB,               nullable=False, default=list)
    url_ti_hits      = Column(JSONB,               nullable=False, default=list)
    ip_ti_hits       = Column(JSONB,               nullable=False, default=list)
    powershell_hits  = Column(JSONB,               nullable=False, default=list)
    command_hits     = Column(JSONB,               nullable=False, default=list)
    detected_at      = Column(DateTime(timezone=True), default=now_utc)

class ThreatHunt(Base):
    __tablename__ = "threat_hunts"
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_type          = Column(String(20),  nullable=False)
    ioc_value         = Column(Text,        nullable=False)
    status            = Column(String(20),  nullable=False, default="pending")
    group_id          = Column(String(64),  nullable=False, default="default")
    alert_count       = Column(Integer,     nullable=False, default=0)
    event_count       = Column(Integer,     nullable=False, default=0)
    fim_count         = Column(Integer,     nullable=False, default=0)
    risk_level        = Column(String(20))
    timeline          = Column(JSONB)
    analysis          = Column(Text)
    related_alert_ids = Column(JSONB)
    created_by        = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at        = Column(DateTime(timezone=True), default=now_utc)
    completed_at      = Column(DateTime(timezone=True))

class FimWatchPath(Base):
    __tablename__ = "fim_watch_paths"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    path       = Column(Text, nullable=False, unique=True)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)

class FimEvent(Base):
    __tablename__ = "fim_events"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    group_id    = Column(String(64), nullable=False, default="default")
    path        = Column(Text, nullable=False)
    event_type  = Column(String(16), nullable=False)
    sha256      = Column(String(64), nullable=True)
    size_bytes  = Column(BigInteger, nullable=True)
    detected_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc)

class FleetHunt(Base):
    __tablename__ = "fleet_hunts"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name             = Column(String(255), nullable=False)
    description      = Column(Text)
    task_type        = Column(String(50), nullable=False)
    params           = Column(JSONB, nullable=False, default=dict)
    status           = Column(String(20), nullable=False, default="running")
    total_agents     = Column(Integer, nullable=False, default=0)
    completed_agents = Column(Integer, nullable=False, default=0)
    group_id         = Column(String(100), nullable=False, default="default")
    created_by       = Column(UUID(as_uuid=True))
    created_at       = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    tasks            = relationship("AgentTask", back_populates="fleet_hunt")

class AgentTask(Base):
    __tablename__ = "agent_tasks"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id      = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=True)
    fleet_hunt_id = Column(UUID(as_uuid=True), ForeignKey("fleet_hunts.id", ondelete="CASCADE"), nullable=True)
    task_type     = Column(String(50), nullable=False)
    params        = Column(JSONB, nullable=False, default=dict)
    status        = Column(String(20), nullable=False, default="pending")
    result        = Column(JSONB)
    error         = Column(Text)
    created_by    = Column(UUID(as_uuid=True))
    created_at    = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    completed_at  = Column(DateTime(timezone=True))
    fleet_hunt    = relationship("FleetHunt", back_populates="tasks")

class Artifact(Base):
    __tablename__ = "artifacts"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name           = Column(String(255), unique=True, nullable=False)
    description    = Column(Text)
    task_type      = Column(String(50), nullable=False)
    default_params = Column(JSONB, nullable=False, default=dict)
    is_enabled     = Column(Boolean, nullable=False, default=True)
    created_at     = Column(DateTime(timezone=True), nullable=False, default=now_utc)

class YaraRule(Base):
    __tablename__ = "yara_rules"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    content     = Column(Text, nullable=False)
    is_enabled  = Column(Boolean, nullable=False, default=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc)

class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash       = Column(Text, nullable=False, unique=True)
    label            = Column(String(255), nullable=False, default="")
    group_id         = Column(String(100), nullable=False, default="default")
    expires_at       = Column(DateTime(timezone=True), nullable=True)
    is_active        = Column(Boolean, nullable=False, default=True)
    used_at          = Column(DateTime(timezone=True), nullable=True)
    used_by_agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    created_by       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at       = Column(DateTime(timezone=True), default=now_utc)

class ApiKey(Base):
    __tablename__ = "api_keys"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    prefix       = Column(String(32), nullable=False, unique=True)
    secret_hash  = Column(Text, nullable=False)
    name         = Column(String(255), nullable=False)
    group_id     = Column(String(100), nullable=False, default="default")
    permissions  = Column(JSONB, nullable=False, default=list)
    expires_at   = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at   = Column(DateTime(timezone=True), nullable=True)
    created_by   = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at   = Column(DateTime(timezone=True), default=now_utc)

class SlaPolicy(Base):
    __tablename__ = "sla_policies"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id      = Column(String(100), nullable=False)
    severity      = Column(String(20), nullable=False)
    warn_minutes  = Column(Integer, nullable=False)
    breach_minutes = Column(Integer, nullable=False)
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    updated_at    = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    __table_args__ = (UniqueConstraint("group_id", "severity", name="uq_sla_policies_group_severity"),)

class SlaNotification(Base):
    __tablename__ = "sla_notifications"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id    = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    threshold   = Column(String(10), nullable=False)  # "warn" | "breach"
    notified_at = Column(DateTime(timezone=True), default=now_utc)
    __table_args__ = (UniqueConstraint("alert_id", "threshold", name="uq_sla_notifications_alert_threshold"),)

class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    id                   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id             = Column(String(100), nullable=False, unique=True)
    log_retention_days   = Column(Integer, nullable=True)
    alert_retention_days = Column(Integer, nullable=True)
    storage_quota_docs   = Column(Integer, nullable=True)
    created_at           = Column(DateTime(timezone=True), default=now_utc)
    updated_at           = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class IocObservation(Base):
    __tablename__ = "ioc_observations"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id    = Column(String(100), nullable=False)
    indicator   = Column(String(4096), nullable=False)
    ioc_type    = Column(String(20), nullable=False)
    confidence  = Column(Float, nullable=False, default=0.0)
    verdict     = Column(String(20), nullable=False, default="unknown")
    source      = Column(String(100), nullable=False)
    first_seen  = Column(DateTime(timezone=True), default=now_utc)
    last_seen   = Column(DateTime(timezone=True), default=now_utc)
    expires_at  = Column(DateTime(timezone=True), nullable=True)
    raw_ref     = Column(JSONB, nullable=True)
    __table_args__ = (UniqueConstraint("group_id", "indicator", "ioc_type", name="uq_ioc_observations_group_indicator_type"),)

class IocLink(Base):
    __tablename__ = "ioc_links"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id      = Column(UUID(as_uuid=True), ForeignKey("ioc_observations.id", ondelete="CASCADE"), nullable=False)
    group_id    = Column(String(100), nullable=False)
    entity_type = Column(String(20), nullable=False)  # event | alert | rule | case
    entity_id   = Column(String(100), nullable=False)
    linked_at   = Column(DateTime(timezone=True), default=now_utc)
    __table_args__ = (UniqueConstraint("ioc_id", "entity_type", "entity_id", name="uq_ioc_links_ioc_entity"),)

class SavedQuery(Base):
    __tablename__ = "saved_queries"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id    = Column(String(100), nullable=False)
    owner_id    = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name        = Column(String(255), nullable=False)
    query_type  = Column(String(20), nullable=False)  # "logs" | "alerts" | "events" | "hunt"
    query_params = Column(JSONB, nullable=False, default=dict)
    is_shared   = Column(Boolean, nullable=False, default=False)
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class Bookmark(Base):
    __tablename__ = "bookmarks"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id     = Column(String(100), nullable=False)
    owner_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    entity_type  = Column(String(20), nullable=False)  # "alert" | "case" | "ip" | "hostname" | "indicator" | ...
    entity_id    = Column(String(255), nullable=False)
    note         = Column(Text)
    is_shared    = Column(Boolean, nullable=False, default=False)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    __table_args__ = (UniqueConstraint("owner_id", "entity_type", "entity_id", name="uq_bookmarks_owner_entity"),)

class AlertSuppression(Base):
    __tablename__ = "alert_suppressions"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type  = Column(String(20),  nullable=False)  # ip | hostname | user | rule_title
    entity_value = Column(String(255), nullable=False)
    reason       = Column(Text)
    group_id     = Column(String(100), nullable=False, default="default")
    is_active    = Column(Boolean, nullable=False, default=True)
    created_by   = Column(UUID(as_uuid=True))
    created_at   = Column(DateTime(timezone=True), default=now_utc)

class ShiftHandover(Base):
    __tablename__ = "shift_handovers"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id     = Column(String(100), nullable=False, default="default")
    shift_label  = Column(String(50), nullable=False, default="day")  # day|night|morning|evening
    summary      = Column(Text, nullable=False)
    open_alerts  = Column(Integer, nullable=False, default=0)
    open_cases   = Column(Integer, nullable=False, default=0)
    escalations  = Column(Integer, nullable=False, default=0)
    created_by   = Column(UUID(as_uuid=True))
    created_at   = Column(DateTime(timezone=True), default=now_utc)

class HuntSchedule(Base):
    __tablename__ = "hunt_schedules"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name            = Column(String(255), nullable=False)
    ioc_type        = Column(String(20), nullable=False)
    ioc_value       = Column(String(255), nullable=False)
    interval_hours  = Column(Integer, nullable=False, default=24)
    group_id        = Column(String(100), nullable=False, default="default")
    is_enabled      = Column(Boolean, nullable=False, default=True)
    last_run_at     = Column(DateTime(timezone=True))
    created_by      = Column(UUID(as_uuid=True))
    created_at      = Column(DateTime(timezone=True), default=now_utc)


class SopDocument(Base):
    __tablename__ = "sop_documents"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id     = Column(String(100), nullable=False, default="default")
    filename     = Column(String(500), nullable=False)
    content_type = Column(String(100), nullable=False, default="text/plain")
    raw_text     = Column(Text, nullable=False)
    status       = Column(String(20), nullable=False, default="pending")
    uploaded_by  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class SopChunk(Base):
    __tablename__ = "sop_chunks"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id  = Column(UUID(as_uuid=True), ForeignKey("sop_documents.id", ondelete="CASCADE"),
                          nullable=False)
    group_id     = Column(String(100), nullable=False, default="default")
    chunk_index  = Column(Integer, nullable=False)
    chunk_text   = Column(Text, nullable=False)
    created_at   = Column(DateTime(timezone=True), default=now_utc)

class AiFeedback(Base):
    """Analyst rating of an AI triage verdict (alert or case). Feeds the RAG
    index (see worker/worker/rag.py index_feedback/retrieve_feedback_context)
    so future triage prompts surface past corrections instead of repeating
    them — retrieval-based adaptation rather than model fine-tuning."""
    __tablename__ = "ai_feedback"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type     = Column(String(20), nullable=False)   # "alert" | "case"
    entity_id       = Column(UUID(as_uuid=True), nullable=False)
    context_text    = Column(Text, nullable=False)         # title/description snapshot, embedded for retrieval
    ai_verdict      = Column(String(50))
    rating          = Column(String(20), nullable=False)   # "correct" | "incorrect"
    correct_verdict = Column(String(50))
    note            = Column(Text)
    group_id        = Column(String(100), nullable=False, default="default")
    created_by      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at      = Column(DateTime(timezone=True), default=now_utc)

class CustomComplianceControl(Base):
    """User-defined compliance control scoped to a single endpoint — lets an
    analyst track an organization-specific requirement that the framework
    controls in app/services/compliance.py don't cover.

    Two modes, distinguished by whether `rules` is populated: manual (empty
    `rules`) has status/evidence typed in directly by an analyst; automated
    (non-empty `rules`) ships those rules to the owning agent over the next
    heartbeat (see routes/ingest.py's heartbeat handler and
    agent/internal/sca's rule DSL) for it to evaluate locally like any
    built-in policy check, and the hygiene-ingest route
    (routes/hygiene.py) writes the agent's verdict back into status/evidence
    on every report — so for an automated control those two columns are
    agent-computed, not analyst-typed, even though the schema doesn't
    enforce that distinction structurally."""
    __tablename__ = "custom_compliance_controls"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id     = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    framework_id = Column(String(50))  # optional tag: "iso27001" | "pci_dss" | "soc2" | None
    title        = Column(String(255), nullable=False)
    description  = Column(Text)
    status       = Column(String(20), nullable=False, default="gap")  # met | partial | gap
    evidence     = Column(Text)
    rules        = Column(JSONB, nullable=False, default=list)  # SCA DSL rule strings — non-empty means "automated"
    condition    = Column(String(10))  # all | any | none — how `rules` combine; only meaningful when rules is non-empty
    group_id     = Column(String(100), nullable=False, default="default")
    created_by   = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class SoarPlaybook(Base):
    __tablename__ = "soar_playbooks"
    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name               = Column(String(255), nullable=False)
    description        = Column(Text)
    trigger_conditions = Column(JSONB, nullable=False, default=dict)
    is_enabled         = Column(Boolean, nullable=False, default=True)
    group_id           = Column(String(100), nullable=False, default="default")
    created_at         = Column(DateTime(timezone=True), default=now_utc)
    updated_at         = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class SoarAction(Base):
    __tablename__ = "soar_actions"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("soar_playbooks.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(50), nullable=False)
    order_index = Column(Integer, nullable=False, default=0)
    params      = Column(JSONB, nullable=False, default=dict)
    created_at  = Column(DateTime(timezone=True), default=now_utc)

class SoarWorkflow(Base):
    __tablename__ = "soar_workflows"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(255), nullable=False)
    description = Column(Text)
    is_enabled  = Column(Boolean, nullable=False, default=True)
    group_id    = Column(String(100), nullable=False, default="default")
    created_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)

class SoarNode(Base):
    __tablename__ = "soar_nodes"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id = Column(UUID(as_uuid=True), ForeignKey("soar_workflows.id", ondelete="CASCADE"), nullable=False)
    node_type   = Column(String(50), nullable=False)
    name        = Column(String(255), nullable=False)
    config      = Column(JSONB, nullable=False, default=dict)
    pos_x       = Column(Float, nullable=False, default=0)
    pos_y       = Column(Float, nullable=False, default=0)

class SoarEdge(Base):
    __tablename__ = "soar_edges"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id    = Column(UUID(as_uuid=True), ForeignKey("soar_workflows.id", ondelete="CASCADE"), nullable=False)
    source_node_id = Column(UUID(as_uuid=True), ForeignKey("soar_nodes.id", ondelete="CASCADE"), nullable=False)
    source_handle  = Column(String(50), nullable=False, default="out")
    target_node_id = Column(UUID(as_uuid=True), ForeignKey("soar_nodes.id", ondelete="CASCADE"), nullable=False)

class SoarRun(Base):
    __tablename__ = "soar_runs"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id      = Column(UUID(as_uuid=True), ForeignKey("soar_workflows.id", ondelete="CASCADE"), nullable=False)
    status           = Column(String(20), nullable=False, default="pending")
    trigger_type     = Column(String(30), nullable=False)
    trigger_ref      = Column(JSONB, nullable=False, default=dict)
    # Not a FK: the executor traverses graph_snapshot, never soar_nodes, so a
    # run must stay immune to later edits of (or deletes from) its workflow's
    # live node rows (spec §5.2).
    current_node_id  = Column(UUID(as_uuid=True), nullable=True)
    variables        = Column(JSONB, nullable=False, default=dict)
    graph_snapshot   = Column(JSONB, nullable=True)
    pending_node_ids = Column(JSONB, nullable=False, default=list)
    resume_at        = Column(DateTime(timezone=True), nullable=True)
    group_id         = Column(String(100), nullable=False, default="default")
    started_at       = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    finished_at      = Column(DateTime(timezone=True), nullable=True)

class SoarRunStep(Base):
    __tablename__ = "soar_run_steps"
    __table_args__ = (
        UniqueConstraint("run_id", "idempotency_key", name="uq_soar_run_steps_idempotency"),
    )
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id      = Column(UUID(as_uuid=True), ForeignKey("soar_runs.id", ondelete="CASCADE"), nullable=False)
    # Not a FK: see SoarRun.current_node_id above (spec §5.2).
    node_id     = Column(UUID(as_uuid=True), nullable=False)
    action_type = Column(String(50), nullable=False)
    status      = Column(String(20), nullable=False)
    is_destructive = Column(Boolean, nullable=False, default=False)
    is_reversible  = Column(Boolean, nullable=False, default=False)
    actor_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    acted_at       = Column(DateTime(timezone=True), nullable=True)
    idempotency_key = Column(String(255), nullable=False)
    input_hash      = Column(String(64), nullable=False)
    rollback_of_step_id = Column(
        UUID(as_uuid=True),
        ForeignKey("soar_run_steps.id", ondelete="RESTRICT"),
        nullable=True,
    )
    input       = Column(JSONB, nullable=True)
    output      = Column(JSONB, nullable=True)
    error       = Column(Text, nullable=True)
    started_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    finished_at = Column(DateTime(timezone=True), nullable=True)
