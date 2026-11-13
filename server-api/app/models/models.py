# server-api/app/models/models.py
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer,
    String, Text, ARRAY, UniqueConstraint, CheckConstraint, Index, Sequence, text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from pgvector.sqlalchemy import Vector
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
    # Token rotation (ingest.heartbeat): the previous token stays valid until
    # prev_token_expires_at, so an agent that missed the new one isn't locked out.
    token_issued_at        = Column(DateTime(timezone=True), default=now_utc)
    prev_token_hash        = Column(Text)
    prev_token_expires_at  = Column(DateTime(timezone=True))
    token_rotate_requested = Column(Boolean, nullable=False, default=False, server_default="false")
    version      = Column(String(50))
    status       = Column(String(20), nullable=False, default="offline")
    # False while waiting for approval (enrolled with a key that requires it):
    # heartbeats are accepted, logs are dropped and no tasks are sent
    approved     = Column(Boolean, nullable=False, default=True, server_default="true")
    is_isolated  = Column(Boolean, nullable=False, default=False)
    last_seen_at = Column(DateTime(timezone=True))
    flow_poll_at = Column(DateTime(timezone=True))  # last live-response long poll; NULL = no flow runner
    # Tamper baseline (heartbeat integrity): hashes as of integrity_version.
    # A change without a version change raises an agent_integrity_changed event.
    binary_sha256     = Column(String(64))
    config_sha256     = Column(String(64))
    integrity_version = Column(String(50))
    # Set by a "stopping" heartbeat (service_stop / system_shutdown), cleared by
    # the next normal one. The worker reports a stop that lasts (agent_monitor).
    stop_reason       = Column(String(30))
    # last durable-evidence health snapshot (schemas.EvidenceHealth), stamped with server receipt time
    evidence_health    = Column(JSONB)
    evidence_health_at = Column(DateTime(timezone=True))
    web_block_health    = Column(JSONB)
    web_block_health_at = Column(DateTime(timezone=True))
    sensor_health       = Column(JSONB)   # per telemetry sensor, from heartbeats (services/sensor_health.py)
    sensor_health_at    = Column(DateTime(timezone=True))
    # Self-update: rollout ring (0 canary … 2 everyone else) and the agent's
    # last reported update status (schemas.AgentUpdateStatus)
    update_ring        = Column(Integer, nullable=False, default=2, server_default="2")
    update_status      = Column(JSONB)
    update_status_at   = Column(DateTime(timezone=True))
    enrolled_at  = Column(DateTime(timezone=True), default=now_utc)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    log_sources  = relationship("AgentLogSource", back_populates="agent", cascade="all, delete-orphan")
    firewall_rules = relationship("AgentFirewallRule", back_populates="agent", cascade="all, delete-orphan")

class AgentUpdatePolicy(Base):
    """The agent version a group should run. Agents whose ring is at most
    `stage` are offered it; `revision` changes with the target or a retry, so
    agents attempt a version that failed before again."""
    __tablename__ = "agent_update_policies"
    group_id       = Column(String(100), primary_key=True)
    target_version = Column(String(50), nullable=False)
    stage          = Column(Integer, nullable=False, default=0)
    paused         = Column(Boolean, nullable=False, default=False)
    pause_reason   = Column(Text)
    revision       = Column(Integer, nullable=False, default=1)
    max_failures   = Column(Integer, nullable=False, default=1)  # failed or stalled agents that pause the rollout
    updated_by     = Column(UUID(as_uuid=True))
    created_at     = Column(DateTime(timezone=True), default=now_utc)
    updated_at     = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class AgentPolicy(Base):
    """A group's protection policy and exclusions (services/agent_policy.py
    validates `settings`); agents fetch their group's, or "default"'s."""
    __tablename__ = "agent_policies"
    group_id   = Column(String(100), primary_key=True)
    settings   = Column(JSONB, nullable=False, default=dict)
    revision   = Column(Integer, nullable=False, default=1)
    updated_by = Column(String(255))
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

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

class AgentFirewallRule(Base):
    __tablename__ = "agent_firewall_rules"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id   = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    action     = Column(String(16), nullable=False, default="block")
    cidr       = Column(String(64), nullable=False)
    proto      = Column(String(16), nullable=False, default="any")
    port       = Column(Integer, nullable=False, default=0)
    direction  = Column(String(16), nullable=False, default="both")
    ttl_seconds = Column(Integer, nullable=False, default=0)
    reason     = Column(Text, nullable=False, default="")
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(UUID(as_uuid=True))
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    agent      = relationship("Agent", back_populates="firewall_rules")

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
    # "custom" (written here / shipped in rules/) or "sigmahq" (imported ruleset)
    source        = Column(String(20), nullable=False, default="custom", server_default="custom")
    external_id   = Column(String(255))  # the Sigma rule id for imported rules
    sigma_status  = Column(String(20))   # stable / test / experimental
    # sha256 of the content as last imported; differs from content once edited locally
    upstream_hash = Column(String(64))
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
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title            = Column(String(255), nullable=False)
    severity         = Column(String(20), nullable=False, default="medium")
    status           = Column(String(30), nullable=False, default="new")
    rule_id          = Column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"))
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
    context          = Column(JSONB, nullable=False, default=dict)  # why it fired: rule tags, threshold counts, UEBA reasons
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
    actor_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    group_id      = Column(String(100), nullable=False, default="default")
    action        = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id   = Column(Text)
    detail        = Column(JSONB, nullable=False, default=dict)
    created_at    = Column(DateTime(timezone=True), default=now_utc)

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
    collected_at    = Column(DateTime(timezone=True), default=now_utc)

class CaseInvestigation(Base):
    """One AI-driven investigation of a case (services/investigator.py): the
    steps it took — tool calls, live-response flows, artifacts it wrote — and
    its final report, which is also added to the case as an AI note."""
    __tablename__ = "case_investigations"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id          = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id         = Column(String(100), nullable=False, default="default")
    # queued → running → finished | error | cancelled | interrupted (server restarted mid-run)
    status           = Column(String(20), nullable=False, default="queued")
    # while running: planning → collecting ⇄ analyzing → reporting
    phase            = Column(String(20))
    started_by       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    model            = Column(String(100))
    steps            = Column(JSONB, nullable=False, default=list)
    report           = Column(Text)
    # the structured report the Markdown above is rendered from (investigation_ledger.validate_report)
    report_json      = Column(JSONB)
    budget_overrides = Column(JSONB, nullable=False, default=dict)  # {"flows": extra runs an analyst granted}
    # the replica running it (investigator.REPLICA_ID); another replica adopts it once the lease expires
    lease_owner      = Column(String(120))
    lease_expires_at = Column(DateTime(timezone=True))
    # progress a replica that adopts the run resumes from
    rounds_used      = Column(Integer, nullable=False, default=0)
    active_seconds   = Column(Float, nullable=False, default=0.0)
    verdict          = Column(String(30))  # true_positive / false_positive / inconclusive
    error            = Column(Text)
    cancel_requested = Column(Boolean, nullable=False, default=False)
    created_at       = Column(DateTime(timezone=True), default=now_utc)
    updated_at       = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    finished_at      = Column(DateTime(timezone=True))
    commands         = relationship("InvestigationCommand", order_by="InvestigationCommand.created_at",
                                    lazy="selectin", passive_deletes=True)

class InvestigationCommand(Base):
    """A command the AI investigator asked to run on a host. Nothing runs until
    a person approves it (or it matches the admin's auto-approve list); the
    approved argv then goes to the agent's exec plugin as a flow."""
    __tablename__ = "investigation_commands"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    group_id         = Column(String(100), nullable=False, default="default")
    agent_id         = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    hostname         = Column(String(255))
    command          = Column(Text, nullable=False)
    args             = Column(JSONB, nullable=False, default=list)
    timeout          = Column(Integer, nullable=False, default=60)
    reason           = Column(Text)
    # pending → approved | rejected | expired (the investigation ended first)
    status           = Column(String(20), nullable=False, default="pending", index=True)
    auto_approved    = Column(Boolean, nullable=False, default=False)
    decided_by       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    decided_at       = Column(DateTime(timezone=True))
    decision_note    = Column(Text)
    flow_id          = Column(UUID(as_uuid=True))
    created_at       = Column(DateTime(timezone=True), default=now_utc)

class InvestigationAction(Base):
    """One step of an investigation's queue: a tool call the AI made or an
    analyst added. The risk tier is the server's (investigation_ledger.py),
    never the model's; the idempotency key keeps endpoint work from repeating."""
    __tablename__ = "investigation_actions"
    __table_args__ = (UniqueConstraint("investigation_id", "idempotency_key", name="uq_investigation_action_key"),)
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id  = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"),
                               nullable=False, index=True)
    group_id          = Column(String(100), nullable=False, default="default")
    ordinal           = Column(Integer, nullable=False)
    kind              = Column(String(20), nullable=False)   # siem_query / artifact / command / authoring / analysis
    tool              = Column(String(60), nullable=False)
    target            = Column(String(255))                  # host as given
    agent_id          = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), index=True)
    params            = Column(JSONB, nullable=False, default=dict)
    reason            = Column(Text)
    expected_evidence = Column(Text)
    risk_tier         = Column(Integer, nullable=False, default=0)
    approval_reason   = Column(Text)                         # why the policy wants a person
    # queued → running → completed | failed | cancelled; queued → awaiting_approval → queued | skipped
    status            = Column(String(20), nullable=False, default="queued", index=True)
    source            = Column(String(20), nullable=False, default="planner")  # planner / replanner / analyst
    dependencies      = Column(JSONB, nullable=False, default=list)
    idempotency_key   = Column(String(64), nullable=False)
    result_ref        = Column(JSONB, nullable=False, default=dict)  # flow_id, command_id, evidence_ids
    error             = Column(Text)
    attempts          = Column(Integer, nullable=False, default=0)
    created_by        = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    decided_by        = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    decided_at        = Column(DateTime(timezone=True))
    decision_note     = Column(Text)
    created_at        = Column(DateTime(timezone=True), default=now_utc)
    started_at        = Column(DateTime(timezone=True))
    finished_at       = Column(DateTime(timezone=True))
    updated_at        = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class InvestigationEvidence(Base):
    """Something an investigation observed. Report claims cite these ids; the
    canonical data (flow rows, events, command output) stays in its own store."""
    __tablename__ = "investigation_evidence"
    __table_args__ = (UniqueConstraint("investigation_id", "content_hash", name="uq_investigation_evidence_hash"),)
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    action_id        = Column(UUID(as_uuid=True), ForeignKey("investigation_actions.id", ondelete="SET NULL"))
    group_id         = Column(String(100), nullable=False, default="default")
    # event / alert / flow_row / file / hash / command_result / ti_result / knowledge_guidance
    evidence_type    = Column(String(30), nullable=False)
    source_type      = Column(String(30), nullable=False)
    source_id        = Column(String(255))
    title            = Column(String(300), nullable=False)
    summary          = Column(Text)
    observed_at      = Column(DateTime(timezone=True))
    entities         = Column(JSONB, nullable=False, default=dict)
    content_hash     = Column(String(64), nullable=False)
    confidence       = Column(Integer)
    sensitivity      = Column(String(20), nullable=False, default="normal")  # normal / sensitive / restricted
    pinned           = Column(Boolean, nullable=False, default=False)
    created_at       = Column(DateTime(timezone=True), default=now_utc)
    updated_at       = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class InvestigationHypothesis(Base):
    """An explanation the investigation is testing, with the evidence for and against it."""
    __tablename__ = "investigation_hypotheses"
    id                         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id           = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"),
                                        nullable=False, index=True)
    group_id                   = Column(String(100), nullable=False, default="default")
    ordinal                    = Column(Integer, nullable=False)
    statement                  = Column(Text, nullable=False)
    state                      = Column(String(20), nullable=False, default="open")  # open/supported/refuted/inconclusive/superseded
    confidence                 = Column(Integer, nullable=False, default=50)
    supporting_evidence_ids    = Column(JSONB, nullable=False, default=list)
    contradicting_evidence_ids = Column(JSONB, nullable=False, default=list)
    open_questions             = Column(JSONB, nullable=False, default=list)
    superseded_by              = Column(UUID(as_uuid=True))
    source                     = Column(String(20), nullable=False, default="planner")
    history                    = Column(JSONB, nullable=False, default=list)
    created_at                 = Column(DateTime(timezone=True), default=now_utc)
    updated_at                 = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class InvestigationMessage(Base):
    """One turn of the follow-up chat on an investigation that has ended
    (services/investigation_chat.py): the analyst's message, the AI's answer
    with the tool calls it made, or a system note (an action's outcome)."""
    __tablename__ = "investigation_messages"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    group_id         = Column(String(100), nullable=False, default="default")
    role             = Column(String(20), nullable=False)  # user / assistant / system
    content          = Column(Text, nullable=False, default="")
    author_id        = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    tool_calls       = Column(JSONB, nullable=False, default=list)
    created_at       = Column(DateTime(timezone=True), default=now_utc)

class InvestigationChatAction(Base):
    """An action the chat AI proposed. Nothing runs until an analyst with the
    right permission approves it; the outcome is stored here."""
    __tablename__ = "investigation_chat_actions"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    message_id       = Column(UUID(as_uuid=True), ForeignKey("investigation_messages.id", ondelete="SET NULL"))
    group_id         = Column(String(100), nullable=False, default="default")
    tool             = Column(String(60), nullable=False)
    target           = Column(String(500))
    params           = Column(JSONB, nullable=False, default=dict)
    reason           = Column(Text)
    # proposed → approved → executed | failed; proposed → rejected | expired (24 h)
    status           = Column(String(20), nullable=False, default="proposed", index=True)
    result           = Column(JSONB)
    error            = Column(Text)
    requested_by     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    decided_by       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    decided_at       = Column(DateTime(timezone=True))
    executed_at      = Column(DateTime(timezone=True))
    created_at       = Column(DateTime(timezone=True), default=now_utc)

class CaseAlert(Base):
    __tablename__ = "case_alerts"
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, index=True)
    status = Column(String(20), nullable=False, default="linked")
    method = Column(String(20), nullable=False, default="ai")
    reason = Column(Text, nullable=False, default="")
    confidence = Column(Float)
    indicators = Column(JSONB, nullable=False, default=list)
    accounts = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class SoarCaseEvent(Base):
    __tablename__ = "soar_case_events"
    id = Column(UUID(as_uuid=True), primary_key=True)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    group_id = Column(String(100), nullable=False)
    event = Column(String(40), nullable=False)
    ready = Column(Boolean, nullable=False, default=True)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), default=now_utc)
    processed_at = Column(DateTime(timezone=True), index=True)


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
    reasons          = Column(JSONB,               nullable=False, default=list)  # why it was anomalous (worker/ueba/explain.py)
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
    # "ai_draft": saved from a YARA draft (services/yara_drafting.py); stays disabled until validated and tested
    origin      = Column(String(20), nullable=False, default="manual")
    draft_id    = Column(UUID(as_uuid=True))
    # services/yara_capability.py: each result names the content fingerprint it is for; an edit voids it
    validation  = Column(JSONB)   # {"ok", "error", "line", "fingerprint", "engine_version", "at", "quality"}
    test_result = Column(JSONB)   # {"status", "fingerprint", "results": [...], "at"}
    activated_by = Column(UUID(as_uuid=True))
    activated_at = Column(DateTime(timezone=True))

class YaraDraft(Base):
    """A YARA rule the AI drafted from one suspicious file's features (never the
    file itself), for an analyst to review. collecting → drafting → draft,
    or failed / dismissed. Saving it creates a disabled yara_rules row."""
    __tablename__ = "yara_drafts"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id         = Column(String(100), nullable=False, default="default")
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    case_id          = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    evidence_id      = Column(UUID(as_uuid=True))                       # the file observation it started from
    host             = Column(String(255))
    agent_id         = Column(UUID(as_uuid=True))
    path             = Column(Text)
    sha256           = Column(String(64), nullable=False, index=True)
    status           = Column(String(20), nullable=False, default="collecting")
    flow_id          = Column(UUID(as_uuid=True))
    features         = Column(JSONB)                                   # bounded, credentials redacted
    support          = Column(JSONB, nullable=False, default=list)      # findings that made the file eligible
    rule_name        = Column(String(128))
    rule_text        = Column(Text)
    rationale        = Column(JSONB, nullable=False, default=list)      # [{id, value, why}]
    limitations      = Column(JSONB, nullable=False, default=list)
    false_positives  = Column(JSONB, nullable=False, default=list)
    quality          = Column(JSONB, nullable=False, default=dict)      # {"blocking": [...], "warnings": [...]}
    confidence       = Column(Integer)
    mitre            = Column(JSONB, nullable=False, default=list)
    tags             = Column(JSONB, nullable=False, default=list)
    error            = Column(Text)
    yara_rule_id     = Column(UUID(as_uuid=True))
    created_by       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at       = Column(DateTime(timezone=True), default=now_utc)
    updated_at       = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash       = Column(Text, nullable=False, unique=True)
    label            = Column(String(255), nullable=False, default="")
    group_id         = Column(String(100), nullable=False, default="default")
    expires_at       = Column(DateTime(timezone=True), nullable=True)
    is_active        = Column(Boolean, nullable=False, default=True)
    # how many agents may enroll with it; NULL = unlimited (a deployment key).
    # No ORM default: SQLAlchemy would apply it to an explicit None too.
    max_uses         = Column(Integer, nullable=True)
    use_count        = Column(Integer, nullable=False, default=0, server_default="0")
    # agents enrolled with it stay pending until approved in the dashboard
    require_approval = Column(Boolean, nullable=False, default=False, server_default="false")
    used_at          = Column(DateTime(timezone=True), nullable=True)  # last use
    used_by_agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    created_by       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at       = Column(DateTime(timezone=True), default=now_utc)

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

class SyslogSource(Base):
    """A network device that sends syslog to the agentless receiver: messages
    from an address inside `cidr` are queued for `group_id` as `log_type`.
    One CIDR belongs to one group; the most specific CIDR wins."""
    __tablename__ = "syslog_sources"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name          = Column(String(255), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default", index=True)
    cidr          = Column(String(64), nullable=False, unique=True)
    log_type      = Column(String(100), nullable=False)
    enabled       = Column(Boolean, nullable=False, default=True)
    message_count = Column(BigInteger, nullable=False, default=0, server_default="0")
    last_seen_at  = Column(DateTime(timezone=True))
    created_by    = Column(UUID(as_uuid=True))
    created_at    = Column(DateTime(timezone=True), default=now_utc)

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


class KnowledgeEntry(Base):
    """What the AI should know about this environment and about attacks:
    analyst notes ("10.0.0.5 is our Nessus scanner") and reference material
    (PayloadsAllTheThings). Chunked and embedded by the worker
    (worker/knowledge.py) into knowledge_chunks; notes with a scope also match
    alerts exactly on IP, host, user or rule."""
    __tablename__ = "knowledge_entries"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id   = Column(String(100), nullable=False, default="default")  # "*" = every group
    kind       = Column(String(20), nullable=False, default="note")     # note | reference
    source     = Column(String(50), nullable=False, default="analyst")  # analyst | payloadsallthethings
    source_ref = Column(Text)                                            # e.g. "SQL Injection/README.md#Union"
    title      = Column(String(300), nullable=False)
    content    = Column(Text, nullable=False)
    scope      = Column(JSONB, nullable=False, default=dict)             # {"ips": [], "hosts": [], "users": [], "rules": []}
    enabled    = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime(timezone=True))
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    indexed_at = Column(DateTime(timezone=True))                         # NULL or < updated_at: (re)embed
    # Knowledge vault (services/knowledge_vault.py): Markdown articles with frontmatter and [[wikilinks]].
    # Only published, enabled, unexpired entries reach the AI.
    slug         = Column(String(200))                                   # wikilink target, unique per group
    path         = Column(Text)                                          # vault path, e.g. "Windows/PowerShell.md"
    tags         = Column(JSONB, nullable=False, default=list)
    frontmatter  = Column(JSONB, nullable=False, default=dict)
    status       = Column(String(20), nullable=False, default="published")  # draft | published | archived
    trust        = Column(String(20), nullable=False, default="reviewed")   # draft | reviewed | verified | external
    content_type = Column(String(30), nullable=False, default="environment")
    owner_id     = Column(UUID(as_uuid=True))
    reviewed_by  = Column(UUID(as_uuid=True))
    reviewed_at  = Column(DateTime(timezone=True))
    version      = Column(Integer, nullable=False, default=1)
    checksum     = Column(String(64))
    index_error  = Column(Text)                                          # why the last embedding failed


class KnowledgeRevision(Base):
    """An immutable snapshot of an article at one version; restoring one makes a new version."""
    __tablename__ = "knowledge_revisions"
    __table_args__ = (UniqueConstraint("entry_id", "version", name="uq_knowledge_revision_version"),)
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id    = Column(UUID(as_uuid=True), ForeignKey("knowledge_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    version     = Column(Integer, nullable=False)
    title       = Column(String(300), nullable=False)
    content     = Column(Text, nullable=False)
    frontmatter = Column(JSONB, nullable=False, default=dict)
    status      = Column(String(20), nullable=False)
    author_id   = Column(UUID(as_uuid=True))
    note        = Column(Text)                                           # e.g. "restored version 2", "imported"
    created_at  = Column(DateTime(timezone=True), default=now_utc)


class KnowledgeLink(Base):
    """A [[wikilink]] from one article; target_id is set once an article with that slug or title exists."""
    __tablename__ = "knowledge_links"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id   = Column(UUID(as_uuid=True), ForeignKey("knowledge_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id    = Column(String(100), nullable=False, default="default")
    target      = Column(String(300), nullable=False)                    # as written
    target_slug = Column(String(200), nullable=False, index=True)
    heading     = Column(String(300))
    target_id   = Column(UUID(as_uuid=True), ForeignKey("knowledge_entries.id", ondelete="SET NULL"), index=True)


class KnowledgeUsage(Base):
    """Each time the AI retrieved or cited a knowledge entry."""
    __tablename__ = "knowledge_usage"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id         = Column(UUID(as_uuid=True), ForeignKey("knowledge_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id         = Column(String(100), nullable=False, default="default")
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("case_investigations.id", ondelete="CASCADE"), index=True)
    case_id          = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"))
    use_type         = Column(String(20), nullable=False)                # retrieved | cited
    query            = Column(Text)
    heading          = Column(String(300))
    version          = Column(Integer)
    score            = Column(Float)
    created_at       = Column(DateTime(timezone=True), default=now_utc)


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

class SoarPlaybook(Base):
    __tablename__ = "soar_playbooks"
    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name               = Column(String(255), nullable=False)
    description        = Column(Text)
    trigger_conditions = Column(JSONB, nullable=False, default=dict)
    graph              = Column(JSONB)          # workflow graph; NULL = legacy linear actions
    trigger_event      = Column(String(30))     # from the graph's Trigger node
    is_enabled         = Column(Boolean, nullable=False, default=True)
    group_id           = Column(String(100), nullable=False, default="default")
    created_at         = Column(DateTime(timezone=True), default=now_utc)
    updated_at         = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class SoarRun(Base):
    __tablename__ = "soar_playbook_runs"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id   = Column(UUID(as_uuid=True), ForeignKey("soar_playbooks.id", ondelete="CASCADE"), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default")
    status        = Column(String(20), nullable=False, default="queued")  # queued|running|waiting|resume|success|failed|cancelled
    trigger_event = Column(String(30), nullable=False)
    alert_id      = Column(UUID(as_uuid=True))
    graph         = Column(JSONB, nullable=False)   # snapshot, so edits don't change a run in flight
    context       = Column(JSONB, nullable=False, default=dict)
    waiting_node  = Column(String(40))
    wait_until    = Column(DateTime(timezone=True))
    error         = Column(Text)
    created_by    = Column(UUID(as_uuid=True))
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    updated_at    = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    finished_at   = Column(DateTime(timezone=True))

class SoarRunStep(Base):
    __tablename__ = "soar_playbook_run_steps"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id      = Column(UUID(as_uuid=True), ForeignKey("soar_playbook_runs.id", ondelete="CASCADE"), nullable=False)
    node_id     = Column(String(40), nullable=False)
    node_type   = Column(String(20), nullable=False)
    status      = Column(String(20), nullable=False)   # success|error|waiting
    output_name = Column(String(20))
    input       = Column(JSONB)
    output      = Column(JSONB)
    error       = Column(Text)
    attempts    = Column(Integer, nullable=False, default=1)
    started_at  = Column(DateTime(timezone=True), default=now_utc)
    duration_ms = Column(Integer)

class SoarAction(Base):
    __tablename__ = "soar_actions"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("soar_playbooks.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(50), nullable=False)
    order_index = Column(Integer, nullable=False, default=0)
    params      = Column(JSONB, nullable=False, default=dict)
    created_at  = Column(DateTime(timezone=True), default=now_utc)

# ─── Live response flows (artifact collections) ──────────────────

class FlowArtifact(Base):
    """Custom artifact YAML; built-ins live in app/artifacts/ and are never stored."""
    __tablename__ = "flow_artifacts"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    content     = Column(Text, nullable=False)
    group_id    = Column(String(100), nullable=False, default="default")
    created_by  = Column(UUID(as_uuid=True))
    # AI.* artifacts: the investigation that wrote it; other runs need it promoted (or approved) to reuse it
    created_by_investigation_id = Column(UUID(as_uuid=True))
    promoted_at = Column(DateTime(timezone=True))
    promoted_by = Column(UUID(as_uuid=True))
    created_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)

class Flow(Base):
    """One artifact collection on one agent: scheduled → running → finished|error|cancelled."""
    __tablename__ = "flows"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id         = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact         = Column(String(100), nullable=False)
    artifact_content = Column(Text, nullable=False)  # snapshot: later edits don't change a past flow
    params           = Column(JSONB, nullable=False, default=dict)
    request          = Column(JSONB, nullable=False, default=dict)
    status           = Column(String(20), nullable=False, default="scheduled", index=True)
    cancel_pending   = Column(Boolean, nullable=False, default=False)
    total_rows       = Column(Integer, nullable=False, default=0)
    error            = Column(Text)
    timeout          = Column(Integer, nullable=False)
    max_rows         = Column(Integer, nullable=False)
    created_by       = Column(UUID(as_uuid=True))
    created_at       = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    started_at       = Column(DateTime(timezone=True))
    completed_at     = Column(DateTime(timezone=True))

class FlowRowBatch(Base):
    __tablename__ = "flow_row_batches"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    flow_id    = Column(UUID(as_uuid=True), ForeignKey("flows.id", ondelete="CASCADE"), nullable=False, index=True)
    source     = Column(String(64), nullable=False)
    rows       = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)

class FlowLog(Base):
    __tablename__ = "flow_logs"
    id      = Column(BigInteger, primary_key=True, autoincrement=True)
    flow_id = Column(UUID(as_uuid=True), ForeignKey("flows.id", ondelete="CASCADE"), nullable=False, index=True)
    ts      = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    level   = Column(String(10), nullable=False, default="info")
    message = Column(Text, nullable=False)


class EvidenceInbox(Base):
    """Durable receipt, retained even after agent deletion.

    payload is a JSONB *scalar string* containing canonical envelope JSON.
    Consumers use json.loads(payload). This preserves NUL log characters, which
    PostgreSQL rejects in JSONB object string values, and all timestamp digits.
    payload_bytes charges the UTF-8 JSON serialization of that scalar, including
    its outer escaping; it is independent of the Go wire-event size limit.
    """
    __tablename__ = "evidence_inbox"
    __table_args__ = (
        UniqueConstraint("agent_id", "event_id", name="uq_evidence_inbox_agent_event"),
        CheckConstraint("status IN ('pending', 'completed', 'dead_letter')", name="ck_evidence_status"),
        CheckConstraint("payload_bytes >= 0", name="ck_evidence_payload_bytes"),
        Index("idx_evidence_dispatch", "next_dispatch_at", postgresql_where=text("status = 'pending'")),
        Index("idx_evidence_attempt", "next_attempt_at", postgresql_where=text("status = 'pending'")),
        Index("idx_evidence_retention", "completed_at", postgresql_where=text("status = 'completed'")),
    )
    receipt_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), nullable=False)
    event_id = Column(UUID(as_uuid=True), nullable=False)
    group_id = Column(String(100), nullable=False)
    hostname = Column(String(255), nullable=False)
    payload_digest = Column(String(64), nullable=False)
    payload = Column(JSONB, nullable=True)
    payload_bytes = Column(BigInteger, nullable=False)
    collected_at = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, default=now_utc, server_default=text("now()"))
    status = Column(String(20), nullable=False, default="pending", server_default="pending")
    failure_count = Column(Integer, nullable=False, default=0, server_default="0")
    last_error = Column(Text, nullable=True)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=now_utc, server_default=text("now()"))
    next_dispatch_at = Column(DateTime(timezone=True), nullable=False, default=now_utc, server_default=text("now()"))
    dispatch_count = Column(Integer, nullable=False, default=0, server_default="0")
    completed_at = Column(DateTime(timezone=True), nullable=True)


class EvidenceGroupUsage(Base):
    __tablename__ = "evidence_group_usage"
    __table_args__ = (CheckConstraint("payload_bytes >= 0", name="ck_evidence_usage_bytes"),)
    group_id = Column(String(100), primary_key=True)
    payload_bytes = Column(BigInteger, nullable=False, default=0, server_default="0")


_malware_hashes_seq = Sequence("malware_hashes_seq")


class MalwareHash(Base):
    """Known-malware SHA-256 set agents check on exec and on file writes
    (worker/worker/malware_hashes.py: every change takes the next seq, so
    agents sync deltas). source: malwarebazaar, analyst, yara. status:
    active, allowed (analyst verdict: not malware), expired."""
    __tablename__ = "malware_hashes"
    sha256     = Column(String(64), primary_key=True)
    source     = Column(String(20), nullable=False)
    label      = Column(String(64), nullable=False, default="", server_default="")
    file_type  = Column(String(32), nullable=False, default="", server_default="")
    reference  = Column(String(255), nullable=False, default="", server_default="")
    # TLSH similarity digest ("T1" + 70 hex) when the source has one: agents
    # report files close to it as variants (agent/internal/tlsh)
    tlsh       = Column(String(72), nullable=False, default="", server_default="")
    status     = Column(String(10), nullable=False, default="active", server_default="active")
    seq        = Column(BigInteger, _malware_hashes_seq, server_default=_malware_hashes_seq.next_value(),
                        nullable=False, index=True)
    added_by   = Column(String(255))
    first_seen = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    added_at   = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    last_seen  = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    __table_args__ = (Index("ix_malware_hashes_source_status", "source", "status"),)


_web_block_seq = Sequence("web_block_seq")


class WebBlockEntry(Base):
    """A domain the agents of a group block (group_id "*" = feed entry for every
    group that enables feeds). Every change takes the next web_block_seq so
    agents sync deltas (app/services/web_blocks.py)."""
    __tablename__ = "web_block_entries"
    __table_args__ = (
        UniqueConstraint("group_id", "domain", "source", name="uq_web_block_entry"),
        Index("ix_web_block_entries_expiry", "expires_at",
              postgresql_where=text("status = 'active' AND expires_at IS NOT NULL")),
        Index("ix_web_block_entries_group_seq", "group_id", "seq"),
    )
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain            = Column(String(253), nullable=False, index=True)
    group_id          = Column(String(100), nullable=False)
    source            = Column(String(20), nullable=False)        # manual, alert, urlhaus, phishtank
    status            = Column(String(20), nullable=False, default="active")  # active, removed, suppressed
    reason            = Column(Text, nullable=False, default="")
    sample_url        = Column(Text)
    alert_id          = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"))
    created_by        = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at        = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at        = Column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)
    expires_at        = Column(DateTime(timezone=True))
    last_seen_in_feed = Column(DateTime(timezone=True))
    seq               = Column(BigInteger, _web_block_seq, server_default=_web_block_seq.next_value(),
                               nullable=False, index=True)


class WebAllowRule(Base):
    """Domains never web-blocked for a group ("*" = every group; built-ins)."""
    __tablename__ = "web_allowlist"
    __table_args__ = (UniqueConstraint("group_id", "domain", name="uq_web_allow_rule"),)
    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id           = Column(String(100), nullable=False)
    domain             = Column(String(253), nullable=False)
    include_subdomains = Column(Boolean, nullable=False, default=False)
    builtin            = Column(Boolean, nullable=False, default=False)
    enabled            = Column(Boolean, nullable=False, default=True)
    created_by         = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at         = Column(DateTime(timezone=True), nullable=False, default=now_utc)


class WebBlockPolicy(Base):
    """Per-group Web Protection switches and block page; "default" is the fallback."""
    __tablename__ = "web_block_policies"
    group_id         = Column(String(100), primary_key=True)
    enabled          = Column(Boolean, nullable=False, default=False)
    feed_enabled     = Column(Boolean, nullable=False, default=False)
    alert_enabled    = Column(Boolean, nullable=False, default=False)
    alert_block_days = Column(Integer, nullable=False, default=30)
    max_entries      = Column(Integer, nullable=False, default=50000)
    page_html        = Column(Text)  # None = built-in page
    contact          = Column(String(255), nullable=False, default="")
    updated_at       = Column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)
    seq              = Column(BigInteger, _web_block_seq, server_default=_web_block_seq.next_value(), nullable=False)


_ip_block_seq = Sequence("ip_block_seq")


class IPBlockEntry(Base):
    """An IP or CIDR (an IoC) the agents of a group drop (group_id "*" = every
    group). Every change takes the next ip_block_seq so agents sync deltas
    (app/services/ip_blocks.py, agent/internal/ipblock)."""
    __tablename__ = "ip_block_entries"
    __table_args__ = (
        UniqueConstraint("group_id", "cidr", "source", name="uq_ip_block_entry"),
        Index("ix_ip_block_entries_expiry", "expires_at",
              postgresql_where=text("status = 'active' AND expires_at IS NOT NULL")),
        Index("ix_ip_block_entries_group_seq", "group_id", "seq"),
    )
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cidr       = Column(String(43), nullable=False, index=True)      # canonical, e.g. 198.51.100.7/32
    group_id   = Column(String(100), nullable=False)
    source     = Column(String(20), nullable=False)                  # manual, soar, alert, feed
    status     = Column(String(20), nullable=False, default="active")  # active, removed
    reason     = Column(Text, nullable=False, default="")
    alert_id   = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"))
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)
    expires_at = Column(DateTime(timezone=True))
    seq        = Column(BigInteger, _ip_block_seq, server_default=_ip_block_seq.next_value(),
                        nullable=False, index=True)


class ExecPreventionRule(Base):
    """Execution rule enforced by Linux agents (agent/internal/prevent).
    rule_type: hash (value = SHA-256), path (value = executable), dir
    (value = directory), parent (parent = parent basenames, value = child
    basenames, comma separated). action: detect or block."""
    __tablename__ = "exec_prevention_rules"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    rule_type   = Column(String(20), nullable=False)
    value       = Column(Text, nullable=False)
    parent      = Column(Text, nullable=False, default="", server_default="")
    action      = Column(String(10), nullable=False, default="detect", server_default="detect")
    is_enabled  = Column(Boolean, nullable=False, default=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=now_utc)


class EntityRisk(Base):
    """Accumulated risk of a host or user from every alert it is part of
    (Sigma, IOA, IoC matches, behaviour findings, UEBA), decaying with a 24 h
    half-life (worker/worker/entity_risk.py). risk_score is the value at
    updated_at; readers apply the decay to now."""
    __tablename__ = "entity_risk"
    entity_type   = Column(String(20),  primary_key=True)   # host, user
    entity_value  = Column(String(255), primary_key=True)
    group_id      = Column(String(100), primary_key=True)
    risk_score    = Column(Float,   nullable=False, default=0.0)
    peak_score    = Column(Float,   nullable=False, default=0.0)
    alert_count   = Column(Integer, nullable=False, default=0)
    tactics       = Column(JSONB,   nullable=False, default=dict)  # tactic -> last seen (epoch seconds)
    sources       = Column(JSONB,   nullable=False, default=dict)  # sigma/ioa/ioc/behavior/ueba/... -> count
    recent        = Column(JSONB,   nullable=False, default=list)  # last contributions, newest first
    last_alert_at = Column(DateTime(timezone=True))
    risk_alert_at = Column(DateTime(timezone=True))                # last [Risk] alert raised
    updated_at    = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    __table_args__ = (Index("ix_entity_risk_group_score", "group_id", "risk_score"),)
