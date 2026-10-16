"""LangChain tool wrappers over the existing read-only assistant tool executor.

The graph does not re-implement any query: every wrapper delegates to
run_tool(), which already applies group scoping and is the single place the
read-only allow-list is enforced. Settings/user/webhook modules are still never
imported here, so the guarantee holds on the graph path too.
"""
from __future__ import annotations

from langchain_core.tools import StructuredTool
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.assistant_tools import TOOLS, run_tool


def build_tools(db: AsyncSession, group_filter: str | None) -> list[StructuredTool]:
    """One StructuredTool per read-only entry in the allow-list."""
    tools: list[StructuredTool] = []

    for spec in TOOLS:
        name = spec["name"]
        description = spec.get("description", "")
        params = spec.get("parameters") or {}

        properties = {}
        for param, hint in params.items():
            properties[param] = {"type": "string", "description": str(hint)}

        schema = {
            "type": "object",
            "properties": properties,
            "required": ["alert_id"] if name == "get_alert" else (
                ["case_id"] if name == "get_case" else (
                    ["hostname"] if name == "agent_hygiene" else []
                )
            ),
        }

        async def _run(_name=name, **kwargs):
            return await run_tool(_name, kwargs, db, group_filter)

        tools.append(
            StructuredTool.from_function(
                coroutine=_run,
                name=name,
                description=description,
                args_schema=schema,
            )
        )

    return tools
