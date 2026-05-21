# worker/worker/models.py
import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, ARRAY
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

def now_utc():
    return datetime.now(timezone.utc)

class Agent(Base):
    __tablename__ = "agents"
    id       = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id = Column(String(100), nullable=False, default="default")
    hostname = Column(String(255), nullable=False)

class RawLog(Base):
    __tablename__ = "raw_logs"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    log_type    = Column(String(100))
    raw_message = Column(Text, nullable=False)
    received_at = Column(DateTime(timezone=True), default=now_utc)

class Event(Base):
    __tablename__ = "events"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_log_id     = Column(UUID(as_uuid=True), ForeignKey("raw_logs.id", ondelete="SET NULL"))
    agent_id       = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id       = Column(String(100), nullable=False, default="default")
    decoded_fields = Column(JSONB, nullable=False, default=dict)
    event_category = Column(String(100))
    event_action   = Column(String(100))
    source_ip      = Column(String(45))
    user_name      = Column(String(255))
    created_at     = Column(DateTime(timezone=True), default=now_utc)

class Rule(Base):
    __tablename__ = "rules"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title       = Column(String(255), nullable=False, default="Untitled")
    description = Column(Text)
    content     = Column(Text, nullable=False)
    level       = Column(String(20), nullable=False, default="medium")
    tags        = Column(ARRAY(Text), nullable=False, default=list)
    mitre_tags  = Column(ARRAY(Text), nullable=False, default=list)
    is_enabled  = Column(Boolean, nullable=False, default=True)
    group_id    = Column(String(100))

class Decoder(Base):
    __tablename__ = "decoders"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name       = Column(String(255), unique=True, nullable=False)
    log_type   = Column(String(100), nullable=False)
    content    = Column(Text, nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    priority   = Column(Integer, nullable=False, default=100)

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
    assignee_id = Column(UUID(as_uuid=True))
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class WebhookConfig(Base):
    __tablename__ = "webhook_configs"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name       = Column(String(255), nullable=False)
    url        = Column(Text, nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    group_id   = Column(String(100))

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
    status        = Column(String(30), nullable=False, default="open")
    alert_id      = Column(UUID(as_uuid=True))
    assignee_id   = Column(UUID(as_uuid=True))
    ai_reasoning  = Column(Text)
    ioc_data      = Column(JSONB, nullable=False, default=dict)
    search_intel  = Column(JSONB, nullable=False, default=dict)
    created_by_ai = Column(Boolean, nullable=False, default=False)
    escalated_at  = Column(DateTime(timezone=True))
    group_id      = Column(String(100), nullable=False, default="default")
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    updated_at    = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class CaseNote(Base):
    __tablename__ = "case_notes"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id         = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    author_id       = Column(UUID(as_uuid=True))
    content         = Column(Text, nullable=False)
    is_ai_generated = Column(Boolean, nullable=False, default=False)
    created_at      = Column(DateTime(timezone=True), default=now_utc)
