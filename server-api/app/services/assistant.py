# server-api/app/services/assistant.py
"""Read-only SOC chat assistant — a small ReAct-style tool loop on top of
9router. The model is only ever shown TOOLS (server/services/assistant_tools.py);
it has no HTTP access and no import path to settings/users/webhooks, so it
cannot read or touch those regardless of what a prompt asks it to do."""
from __future__ import annotations
import json
import re
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.llm_client import generate_chat
from app.core.llm_gateway import stream as gateway_stream
from app.models.models import PlatformSetting
from app.services.assistant_tools import TOOLS, run_tool

log = structlog.get_logger()

_MAX_TOOL_ROUNDS = 8

_SYSTEM_PROMPT = f"""You are the SOC Assistant embedded in a SIEM platform, helping an analyst by answering questions using live platform data.

SCOPE: You can read alerts, cases, agents, UEBA risk scores, FIM changes, hygiene snapshots, threat hunts, detection rules, and YARA rules. You have NO access to platform settings, user accounts, or webhook configuration — if asked about those, say plainly that you don't have access to that area and suggest the analyst check the Settings/Users/Webhooks pages themselves.

You cannot take any action (you cannot close alerts, escalate cases, run commands, or change anything) — you are read-only. If asked to perform an action, explain you can only look things up and suggest what page/button to use instead.

TOOLS available (call one at a time):
{json.dumps(TOOLS, indent=2)}

PROTOCOL: Respond with ONLY ONE JSON object per turn, no markdown fences, no prose outside the JSON:
- To call a tool: {{"action": "tool", "tool": "<name>", "args": {{...}}}}
- To answer the analyst: {{"action": "final", "message": "<answer in plain text, concise, no markdown headers>"}}

Call tools as needed to answer accurately — don't guess at data. Once you have enough information, respond with "final". If a tool returns an error or empty results, say so plainly rather than making something up. Keep the final message under 150 words — this is a chat reply, not a report."""


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    return (row.value if row and row.value else default)


def _parse_action(raw: str) -> dict | None:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


def _salvage_truncated_message(raw: str) -> str | None:
    """The model sometimes gets cut off mid-answer (max_tokens hit while
    writing the "message" string) — rather than show the analyst a raw,
    broken JSON fragment, pull out whatever text made it into the message
    field before the cutoff."""
    m = re.search(r'"message"\s*:\s*"((?:[^"\\]|\\.)*)', raw, re.DOTALL)
    if not m:
        return None
    text = m.group(1)
    text = text.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
    return text.strip() or None


async def run_assistant_chat(
    db: AsyncSession,
    group_filter: str | None,
    history: list[dict],
    user_message: str,
) -> dict:
    api_key = await _get_setting(db, "ninerouter_api_key", "")
    model = await _get_setting(db, "ninerouter_model", "combo")

    if not api_key:
        return {"reply": "The AI assistant isn't configured yet — an admin needs to set the 9router API key in Settings.", "tools_used": []}

    messages = _build_messages(history, user_message)

    tools_used: list[str] = []
    for i in range(_MAX_TOOL_ROUNDS):
        if i == _MAX_TOOL_ROUNDS - 1:
            # Last round — force a wrap-up instead of another tool call so a
            # busy entity (e.g. an IP with hundreds of alerts) still gets a
            # real answer instead of the generic "couldn't conclude" bailout.
            messages.append({"role": "user", "content": (
                "You're out of tool calls for this turn. Respond now with "
                '{"action": "final", "message": "..."}, summarizing what '
                "you've found so far even if the investigation feels incomplete — "
                "don't call another tool."
            )})
        raw = await generate_chat(api_key, model, messages, max_tokens=2200, db=db)
        if not raw:
            return {"reply": "The AI assistant is unavailable right now — try again in a moment.", "tools_used": tools_used}

        action = _parse_action(raw)
        if not action or action.get("action") not in ("tool", "final"):
            # Malformed or truncated JSON (e.g. max_tokens hit mid-answer) —
            # try to salvage the message text before falling back to raw output.
            salvaged = _salvage_truncated_message(raw)
            return {"reply": salvaged or raw[:2000], "tools_used": tools_used}

        if action["action"] == "final":
            return {"reply": str(action.get("message", ""))[:2000], "tools_used": tools_used}

        tool_name = str(action.get("tool", ""))
        tool_args = action.get("args") or {}
        log.info("assistant_tool_call", tool=tool_name, args=tool_args)
        result = await run_tool(tool_name, tool_args, db, group_filter)
        tools_used.append(tool_name)

        messages.append({"role": "assistant", "content": raw})
        messages.append({"role": "user", "content": f"TOOL RESULT for {tool_name}: {json.dumps(result, default=str)[:4000]}"})

    return {"reply": "I looked into this but couldn't reach a conclusive answer in time — try narrowing your question.", "tools_used": tools_used}


def _build_messages(history: list[dict], user_message: str) -> list[dict]:
    messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
    for h in history[-10:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": str(h["content"])[:2000]})
    messages.append({"role": "user", "content": user_message[:2000]})
    return messages


async def stream_assistant_chat(
    db: AsyncSession,
    group_filter: str | None,
    history: list[dict],
    user_message: str,
):
    """Streaming variant of run_assistant_chat for the dashboard.

    The tool loop is single-pass here: the gateway streams the model's reply as
    it arrives, and if that reply is a tool call rather than a final answer, the
    tool runs once and its result is streamed back as a follow-up turn. This
    keeps the read-only guarantee identical to the non-streaming path — the
    model can only reach run_tool(), which is the same allow-list.
    """
    api_key = await _get_setting(db, "ninerouter_api_key", "")
    model = await _get_setting(db, "ninerouter_model", "combo")

    if not api_key:
        yield {"type": "error", "message": "The AI assistant isn't configured yet — an admin needs to set the 9router API key in Settings."}
        return

    messages = _build_messages(history, user_message)

    for i in range(_MAX_TOOL_ROUNDS):
        buffered = ""
        async for chunk in gateway_stream(db, messages, model=model, max_tokens=2200):
            if chunk.get("type") == "text-delta":
                buffered += chunk.get("text", "")
                yield chunk
            elif chunk.get("type") == "reasoning-delta":
                yield chunk
            elif chunk.get("type") == "error":
                yield chunk
                return
            elif chunk.get("type") == "finish":
                pass

        action = _parse_action(buffered)
        if not action or action.get("action") not in ("tool", "final"):
            salvaged = _salvage_truncated_message(buffered)
            if salvaged:
                yield {"type": "text-delta", "text": salvaged}
            yield {"type": "finish"}
            return

        if action["action"] == "final":
            yield {"type": "finish"}
            return

        tool_name = str(action.get("tool", ""))
        tool_args = action.get("args") or {}
        log.info("assistant_tool_call", tool=tool_name, args=tool_args)
        result = await run_tool(tool_name, tool_args, db, group_filter)
        yield {"type": "tool-call", "tool": tool_name, "args": tool_args}

        messages.append({"role": "assistant", "content": buffered})
        messages.append({
            "role": "user",
            "content": f"TOOL RESULT for {tool_name}: {json.dumps(result, default=str)[:4000]}",
        })

    yield {"type": "finish"}
