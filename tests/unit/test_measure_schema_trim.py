"""Check captured-baseline selection and production trim measurements."""

from copy import deepcopy
import json

import pytest

from tools.context_analysis.measure_schema_trim import load_tools, measure_trim, metrics


def test_selects_last_nonempty_schema_or_explicit_physical_line(tmp_path):
    first = [{"type": "function", "function": {"name": "ghidra_first"}}]
    last = [{"type": "function", "function": {"name": "ghidra_last"}}]
    log = tmp_path / "request.jsonl"
    log.write_text("\n".join([
        json.dumps({"request_body": {"tools": first}}),
        "",
        json.dumps({"request_body": {"tools": last}}),
        json.dumps({"request_body": {"tools": []}}),
        json.dumps({"usage": {"in": 999}}),
    ]), encoding="utf-8")
    assert load_tools(log) == (last, 3)
    assert load_tools(log, 1) == (first, 1)
    with pytest.raises(ValueError, match="line 4"):
        load_tools(log, 4)
    with pytest.raises(ValueError, match="line 20"):
        load_tools(log, 20)
    with pytest.raises(ValueError, match="positive"):
        load_tools(log, 0)


@pytest.mark.parametrize("prefix", ["ghidra_", "custom_", ""])
def test_measurement_counts_compaction_and_disabled_filter_separately(prefix):
    literal = {"title": "données", "description": ""}
    tools = [
        {
            "type": "function",
            "function": {
                "name": prefix + "get_functions",
                "description": "Tool-specific guidance stays.",
                "parameters": {
                    "title": "Arguments",
                    "properties": {"value": {"type": "object", "description": "", "default": literal}},
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": prefix + "clear_flow_and_repair",
                "parameters": {"type": "object"},
            },
        },
        {"type": "custom", "name": "other_protocol_tool"},
    ]
    if prefix:
        tools.append({"type": "function", "function": {"name": "unrelated_tool"}})
    before = deepcopy(tools)
    expected_compacted = deepcopy(tools[:2])
    params = expected_compacted[0]["function"]["parameters"]
    del params["title"]
    del params["properties"]["value"]["description"]

    report = measure_trim(tools, prefix)
    assert report["baseline"] == metrics(tools[:2])
    assert report["after_current_compaction"]["characters"] == metrics(expected_compacted)["characters"]
    assert report["after_disabled_tool_filter"]["utf8_bytes"] == metrics(expected_compacted[:1])["utf8_bytes"]
    assert report["after_disabled_tool_filter"]["tools"] == 1
    assert report["disabled_tools_removed"] == [prefix + "clear_flow_and_repair"]
    total_saved = report["after_disabled_tool_filter"]["saved_characters"]
    assert total_saved == (
        report["compaction_only_saved_characters"] + report["disabled_filter_only_saved_characters"]
    )
    assert total_saved > report["compaction_only_saved_characters"] > 0
    assert report["baseline"]["utf8_bytes"] > report["baseline"]["characters"]
    assert tools == before


def test_missing_matching_tools_is_an_error():
    with pytest.raises(ValueError, match="No function tools match"):
        measure_trim([])
