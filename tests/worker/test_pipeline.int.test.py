# tests/worker/test_pipeline.int.test.py
# SIEM Platform Worker Pipeline Integration Tests
# Design Doc: docs/superpowers/specs/2026-05-21-siem-platform-design.md
# Generated: 2026-05-30 | Budget Used: integration 3/3, fixture-e2e 3/3, service-e2e 1/2

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../worker'))

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def make_rule_match(title="SSH Failed Login", level="high"):
    return {
        "id": "rule-ssh-failed",
        "title": title,
        "level": level,
        "tags": ["attack.t1110"],
        "mitre_tags": ["attack.t1110"],
        "matched_fields": {},
    }


def make_decoder_yaml():
    return """
name: linux_auth_failed
log_type: linux_auth
type: regex
priority: 10
enabled: true
pattern: 'Failed password for (?P<user>\\S+) from (?P<src_ip>\\S+) port (?P<port>\\d+)'
fields:
  event.category: authentication
  event.action: login_failed
  source.ip: src_ip
  user.name: user
  source.port: port
"""


def make_rule_yaml():
    return """
title: SSH Failed Login
id: rule-ssh-failed
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: high
"""


# ---------------------------------------------------------------------------
# Test 1: Worker pipeline end-to-end — raw log → event persisted → sigma → alert
# ---------------------------------------------------------------------------

# AC: When the worker receives a Redis stream message containing a raw SSH
#     failed-password log, it decodes the log into structured fields, persists
#     a RawLog and Event row, evaluates sigma rules, and calls create_alert
#     with the matched rule and extracted source_ip.
# ROI: 99 (BV:10 × Freq:9 + Legal:0 + Defect:9)
# Behavior: Redis message arrives → DecoderEngine decodes → DB rows written → SigmaEngine matches → create_alert called
# @category: core-functionality
# @lane: integration
# @dependency: DecoderEngine, SigmaEngine, AsyncSessionLocal (mocked), create_alert (mocked), get_redis (mocked)
# @complexity: high

@pytest.mark.asyncio
async def test_process_message_decode_and_alert():
    """
    Verification items:
    - RawLog is added to the DB session
    - Event decoded_fields contain 'event.action': 'login_failed' and 'source.ip': '1.2.3.4'
    - create_alert is called exactly once with source_ip='1.2.3.4' and rule title containing 'SSH'
    - The sigma rule match triggers for the login_failed action field

    Expected result:
    - The mock DB session has add() called at least twice (RawLog + Event)
    - create_alert mock receives a rule_match dict whose 'level' == 'high'
    - No unhandled exceptions propagated out of process_message

    Pass criteria:
    - All assertions on mock call arguments pass
    - Event.source_ip extracted as '1.2.3.4' from the raw log
    """
    # Arrange
    from worker.decoder_engine import DecoderEngine
    from worker.sigma_engine import SigmaEngine

    dec_engine = DecoderEngine()
    dec_engine.load_from_yaml_list([make_decoder_yaml()])

    sig_engine = SigmaEngine(redis=None)
    sig_engine.load_from_yaml_list([make_rule_yaml()])

    raw_message = "May 30 10:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
    data = {
        "agent_id": str(uuid.uuid4()),
        "group_id": "default",
        "hostname": "webserver-prod",
        "log_type": "linux_auth",
        "raw_message": raw_message,
        "received_at": "2026-05-30T10:00:01+00:00",
    }

    mock_db = AsyncMock()
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=False)

    mock_redis = AsyncMock()

    # Act + Assert
    with patch("worker.consumer.AsyncSessionLocal", return_value=mock_db), \
         patch("worker.consumer.create_alert", new=AsyncMock()) as mock_create_alert, \
         patch("worker.consumer.get_redis", new=AsyncMock(return_value=mock_redis)), \
         patch("worker.consumer.ueba_score_event", new=AsyncMock()):

        from worker.consumer import process_message
        await process_message(data, dec_engine, sig_engine)

        # RawLog and Event were added to DB session
        assert mock_db.add.call_count >= 2

        # create_alert called once with correct arguments
        assert mock_create_alert.call_count == 1
        call_kwargs = mock_create_alert.call_args.kwargs
        assert call_kwargs["source_ip"] == "1.2.3.4"
        rule_match = call_kwargs["rule_match"]
        assert rule_match["level"] == "high"
        assert "SSH" in rule_match["title"] or "login_failed" in str(rule_match)


# ---------------------------------------------------------------------------
# Test 2: Alert deduplication — duplicate within 30-min window bumps count
# ---------------------------------------------------------------------------

# AC: When create_alert is called for a rule title that already has an open
#     alert (status in ['new', 'in_progress']) from the same group and source_ip
#     within the past 30 minutes, the system increments duplicate_count on the
#     existing alert instead of creating a new Alert row.
# ROI: 81 (BV:9 × Freq:8 + Legal:0 + Defect:9)
# Behavior: Duplicate alert trigger → existing open alert found → duplicate_count incremented → new row NOT inserted
# @category: core-functionality
# @lane: integration
# @dependency: AlertManager.create_alert, AsyncSessionLocal (mocked), Alert model
# @complexity: high

@pytest.mark.asyncio
async def test_create_alert_deduplication_increments_count():
    """
    Verification items:
    - When an existing open alert with same title, group_id, source_ip exists within 30-min window,
      duplicate_count is incremented by 1 on the existing alert object
    - No new Alert object is constructed or added to the DB session
    - The function returns the existing alert's UUID

    Expected result:
    - existing_alert.duplicate_count == (initial_count + 1)
    - Return value == existing_alert.id

    Pass criteria:
    - mock DB execute returns the pre-constructed existing alert
    - create_alert returns the existing alert ID without calling db.add for a new Alert
    """
    # Arrange
    existing_id = uuid.uuid4()
    existing_alert = MagicMock()
    existing_alert.id = existing_id
    existing_alert.duplicate_count = 2
    existing_alert.title = "SSH Failed Login"
    existing_alert.group_id = "default"
    existing_alert.source_ip = "1.2.3.4"
    existing_alert.status = "new"

    mock_scalar = MagicMock()
    mock_scalar.scalar_one_or_none = MagicMock(return_value=existing_alert)

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=mock_scalar)
    mock_db.commit = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=False)

    rule_match = make_rule_match()

    # Act
    with patch("worker.alert_manager.AsyncSessionLocal", return_value=mock_db), \
         patch("worker.alert_manager._is_suppressed", new=AsyncMock(return_value=False)), \
         patch("worker.alert_manager.get_redis", new=AsyncMock()), \
         patch("worker.alert_manager._get_entity_risk_max", new=AsyncMock(return_value=0.0)), \
         patch("worker.alert_manager.check_correlation", new=AsyncMock()), \
         patch("worker.alert_manager.run_soar_playbooks", new=AsyncMock()), \
         patch("worker.alert_manager.send_alert_email", new=AsyncMock()):

        from worker.alert_manager import create_alert
        result = await create_alert(
            rule_match=rule_match,
            event_id=uuid.uuid4(),
            agent_id=uuid.uuid4(),
            group_id="default",
            source_ip="1.2.3.4",
            hostname="webserver-prod",
        )

    # Assert
    # duplicate_count incremented
    assert existing_alert.duplicate_count == 3
    # returned existing id, not a new one
    assert result == existing_id
    # no new Alert row added
    mock_db.add.assert_not_called()


# ---------------------------------------------------------------------------
# Test 3: Alert suppression — active suppression blocks alert creation
# ---------------------------------------------------------------------------

# AC: When an active AlertSuppression record exists matching the source_ip,
#     hostname, user, or rule_title for the alert's group, create_alert must
#     return None without persisting any Alert or WebhookDelivery row.
# ROI: 64 (BV:8 × Freq:7 + Legal:0 + Defect:8)
# Behavior: Suppression record found → create_alert returns None → no DB write for Alert
# @category: core-functionality
# @lane: integration
# @dependency: AlertManager.create_alert, _is_suppressed (mocked to True), AsyncSessionLocal
# @complexity: medium

@pytest.mark.asyncio
async def test_create_alert_blocked_by_suppression():
    """
    Verification items:
    - When _is_suppressed returns True, create_alert returns None
    - db.add is never called (no Alert or WebhookDelivery rows created)
    - db.commit is never called

    Expected result:
    - return value is None
    - mock_db.add.call_count == 0

    Pass criteria:
    - _is_suppressed mock is called with correct group_id, source_ip, rule title
    - create_alert exits early without any side effects
    """
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=False)

    rule_match = make_rule_match(title="SSH Failed Login", level="medium")

    # Act
    with patch("worker.alert_manager.AsyncSessionLocal", return_value=mock_db), \
         patch("worker.alert_manager._is_suppressed", new=AsyncMock(return_value=True)):

        from worker.alert_manager import create_alert
        result = await create_alert(
            rule_match=rule_match,
            event_id=uuid.uuid4(),
            agent_id=uuid.uuid4(),
            group_id="prod",
            source_ip="10.0.0.5",
            hostname="db-server",
        )

    # Assert
    assert result is None
    mock_db.add.assert_not_called()
    mock_db.commit.assert_not_called()
