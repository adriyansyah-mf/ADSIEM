# tests/server-api/test_investigator_output.py
"""What the investigator does with messy model output: text tool calls, degenerate text, long contexts."""
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from app.services.investigator import CONTEXT_CHARS, TOOL_RESULT_CHARS, _compact, is_degenerate, parse_text_tool_calls

TOOLS = {"run_artifact", "search_events", "create_artifact", "list_hosts"}

# What a real investigation produced through a 9router combo (trimmed).
GARBLED = (
    "We need to gather more evidence about the IP 80.94.92.27. Or we can search for events where the "
    "source_ip is 80.94.92.27 and the destination is" + "<unk>" * 300 + " We need" + "<unk>" * 100
    + ' "AI.Environmental.SoilContamination" </parameter> </function> </tool_call>'
)


def test_garbled_output_is_detected():
    assert is_degenerate(GARBLED)
    assert is_degenerate("Searching the logs. " + "the IP " * 200)


def test_normal_reports_are_not_degenerate():
    report = (
        "## Summary\nBrute force from 80.94.92.27 against web01 (SSH) — no successful logon.\n\n"
        "| Time | Event | Source |\n|---|---|---|\n" + "| 10:00 | login_failed | 80.94.92.27 |\n" * 40
        + "\n---\n" + "C:\\Windows\\System32\\drivers\\etc\\hosts\n" * 3
        + "\n## Recommended actions\n1. Block 80.94.92.27.\n2. Disable password SSH logins.\n\nVERDICT: true_positive"
    )
    assert not is_degenerate(report)
    assert not is_degenerate("")


def test_qwen_xml_tool_calls_are_recovered():
    content = (
        "The host is offline, so search the SIEM logs instead.\n"
        "<tool_call>\n<function=search_events>\n<parameter=source_ip>\n80.94.92.27\n</parameter>\n"
        "<parameter=limit>\n50\n</parameter>\n</function>\n</tool_call>"
    )
    calls, rest = parse_text_tool_calls(content, TOOLS)
    assert [(c["name"], c["args"]) for c in calls] == [("search_events", {"source_ip": "80.94.92.27", "limit": 50})]
    assert rest == "The host is offline, so search the SIEM logs instead."
    assert calls[0]["id"].startswith("text_call_")


def test_hermes_json_tool_calls_are_recovered():
    content = ('<tool_call>{"name": "run_artifact", "arguments": {"artifact": "Linux.Sys.Pslist", '
               '"host": "web01"}}</tool_call>')
    calls, rest = parse_text_tool_calls(content, TOOLS)
    assert [(c["name"], c["args"]) for c in calls] == [("run_artifact", {"artifact": "Linux.Sys.Pslist", "host": "web01"})]
    assert rest == ""


def test_unknown_or_hallucinated_tools_are_ignored():
    content = "<function=format_disk>\n<parameter=drive>\nC:\n</parameter>\n</function>"
    assert parse_text_tool_calls(content, TOOLS) == ([], content)
    assert parse_text_tool_calls("plain answer, no calls", TOOLS) == ([], "plain answer, no calls")


def test_old_tool_results_are_shortened_when_the_context_grows():
    big = "x" * TOOL_RESULT_CHARS  # each tool result is capped at this
    msgs = [SystemMessage(content="sys"), HumanMessage(content="case")] + [
        ToolMessage(content=big, tool_call_id=f"c{i}", name="search_events") for i in range(12)
    ]
    out = _compact(msgs)
    assert sum(len(str(m.content)) for m in out) <= CONTEXT_CHARS
    assert all(len(str(m.content)) == TOOL_RESULT_CHARS for m in out[-3:])  # the latest results stay whole
    assert "older result shortened" in str(out[2].content)
    assert msgs[2].content == big  # the caller's history is untouched
    small = [SystemMessage(content="sys"), ToolMessage(content="ok", tool_call_id="c", name="x")]
    assert _compact(small) == small
