# SIEM Detection Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propagate Sigma detection identity and context from event matching into AI triage and alert/case handling.

**Architecture:** Extend the existing worker match contract and alert model without changing non-Sigma producers. Keep Sigma context optional at AI boundaries, so UEBA and legacy alerts continue to use the current fallback behavior.

**Tech Stack:** Python, FastAPI worker, SQLAlchemy, Redis queue, PySigma, pytest.

**Spec:** `docs/superpowers/specs/2026-09-06-siem-detection-pipeline-design.md`

## Global Constraints

- Preserve group-scoped alert isolation and existing deduplication behavior.
- Never include raw secrets or credentials in AI context.
- Keep Sigma context optional for non-Sigma alert producers.
- Record each completed change in `CHANGELOG.md`.

### Task 1: Persist Sigma rule identity on generated alerts

**Files:**
- Modify: `worker/worker/sigma_engine.py`
- Modify: `worker/worker/alert_manager.py`
- Modify: `worker/worker/models.py` if the alert model lacks a rule reference
- Test: `tests/worker/test_sigma_compat.py`

- [ ] Add a regression test asserting a Sigma match exposes a stable rule identifier and matched fields.
- [ ] Add the minimal persistence/queue mapping needed to retain that identifier.
- [ ] Run the focused worker test and confirm existing UEBA alert construction still works.

### Task 2: Feed Sigma context into AI triage

**Files:**
- Modify: `worker/worker/ai_consumer.py`
- Modify: `worker/worker/ai_analyst.py`
- Modify: `worker/worker/llm_client.py`
- Test: `worker/tests/test_rag.py` or a focused worker AI test

- [ ] Add a test for the AI call receiving optional Sigma context.
- [ ] Pass the context through the queue and include it in the bounded LLM prompt.
- [ ] Verify the no-context fallback remains unchanged.

### Task 3: Verify end-to-end behavior and document the release

**Files:**
- Modify: `CHANGELOG.md`
- Test: `tests/worker/test_sigma_compat.py`, focused AI tests

- [ ] Run syntax, lint, and focused tests in the worker environment.
- [ ] Run a container smoke test that prints the propagated Sigma context.
- [ ] Record the shipped behavior and any pre-existing test limitations in `CHANGELOG.md`.
