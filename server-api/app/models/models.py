# server-api/app/models/models.py
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer,
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
