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

class RawLog(Base):
    __tablename__ = "raw_logs"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    log_type    = Column(String(100))
    raw_message = Column(Text, nullable=False)
    received_at = Column(DateTime(timezone=True), default=now_utc)

class Event(Base):
    __tablename__ = "events"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_log_id      = Column(UUID(as_uuid=True), ForeignKey("raw_logs.id", ondelete="SET NULL"))
    agent_id        = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id        = Column(String(100), nullable=False, default="default")
    decoded_fields  = Column(JSONB, nullable=False, default=dict)
    event_category  = Column(String(100))
    event_action    = Column(String(100))
    source_ip       = Column(String(45))
    user_name       = Column(String(255))
    created_at      = Column(DateTime(timezone=True), default=now_utc)

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
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title       = Column(String(255), nullable=False)
    severity    = Column(String(20), nullable=False, default="medium")
    status      = Column(String(30), nullable=False, default="new")
    rule_id     = Column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"))
    event_id    = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"))
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id    = Column(String(100), nullable=False, default="default")
    source_ip   = Column(String(45))
    hostname    = Column(String(255))
    assignee_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    notes       = relationship("AlertNote", back_populates="alert", cascade="all, delete-orphan")

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
    actor_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    action        = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id   = Column(Text)
    detail        = Column(JSONB, nullable=False, default=dict)
    created_at    = Column(DateTime(timezone=True), default=now_utc)

class WebhookConfig(Base):
    __tablename__ = "webhook_configs"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name       = Column(String(255), nullable=False)
    url        = Column(Text, nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    group_id   = Column(String(100))
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class PlatformSetting(Base):
    __tablename__ = "platform_settings"
    key         = Column(String(100), primary_key=True)
    value       = Column(Text)
    is_secret   = Column(Boolean, nullable=False, default=False)
    description = Column(Text)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    updated_by  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id          = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    webhook_config_id = Column(UUID(as_uuid=True), ForeignKey("webhook_configs.id", ondelete="CASCADE"), nullable=False)
    payload           = Column(JSONB, nullable=False, default=dict)
    status            = Column(String(20), nullable=False, default="pending")
    attempts          = Column(Integer, nullable=False, default=0)
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

class CorrelationRule(Base):
    __tablename__ = "correlation_rules"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title           = Column(String(255), nullable=False)
    description     = Column(Text)
    match_field     = Column(String(100), nullable=False, default="source_ip")
    min_count       = Column(Integer, nullable=False, default=5)
    timewindow      = Column(Integer, nullable=False, default=300)
    severity_filter = Column(String(20))
    output_severity = Column(String(20), nullable=False, default="high")
    output_title    = Column(String(255), nullable=False)
    is_enabled      = Column(Boolean, nullable=False, default=True)
    group_id        = Column(String(100))
    created_at      = Column(DateTime(timezone=True), default=now_utc)
    updated_at      = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
