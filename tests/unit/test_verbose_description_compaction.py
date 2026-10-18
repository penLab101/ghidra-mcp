"""Verbose documentation stays actionable after publication compaction."""

import asyncio
import json
from pathlib import Path

import pytest

from bridge_mcp_ghidra import schema, server, static_tools  # noqa: F401


@pytest.mark.parametrize(
    ("name", "guidance"),
    [
        ("get_functions", ("20", "refs", "call_context", "analyze_function_completeness")),
        ("set_function_this_type", ("EXISTING struct", "auto-storage", "mem:1000")),
        ("get_comment", ("null = never set", "explicitly cleared", "with_comments")),
        ("close_program", ("save=true", "refuses", "save=false discards")),
        (
            "run_script_inline",
            ("failures may persist", "compile errors prevent", "GHIDRA_MCP_ALLOW_SCRIPTS=1", "rejects dry_run=true"),
        ),
    ],
)
def test_large_tool_descriptions_keep_call_guidance(name, guidance):
    catalog = Path(__file__).resolve().parents[1] / "endpoints.json"
    tools = json.loads(catalog.read_text(encoding="utf-8"))["endpoints"]
    description = next(t["description"] for t in tools if t["path"] == f"/{name}")
    compact = schema._compact_description(description)
    assert len(compact) < len(description) * 0.85
    for phrase in guidance:
        assert phrase in compact


def test_static_docstrings_shrink_in_actual_sdk_tool_list():
    raw = {t.name: t for t in asyncio.run(server._orig_list_tools())}
    published = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
    for name in ("connect_instance", "import_file"):
        assert len(published[name].description) < len(raw[name].description) * 0.4
        assert published[name].inputSchema["required"] == raw[name].inputSchema["required"]
    assert "tools/list_changed" in published["connect_instance"].description
    assert "compiler_spec" in published["import_file"].description


def test_exact_rewrites_are_idempotent_and_keep_unknown_qualifications():
    suffix = " Additional endpoint constraint: never change the trace."
    for verbose, _ in schema._DESCRIPTION_REPLACEMENTS:
        compact = schema._compact_description(verbose + suffix)
        assert len(compact) < len(verbose + suffix)
        assert compact.endswith(suffix)
        assert schema._compact_description(compact) == compact
    unknown = "Read function fields with a new restriction: leave program memory unchanged."
    assert schema._compact_description(unknown) == unknown


@pytest.mark.parametrize(
    ("name", "parameter", "guidance"),
    [
        ("add_struct_field", "offset", ("Byte", "-1", "OVERWRITES", "without shifting", "grows")),
        ("get_function_hash", "offset", ("0 = first", "after filtering", "filter fixed")),
        ("apply_documentation", "entries", ("overrides top-level", "per-entry", "failures do not stop")),
        ("apply_documentation", "plate_comment", ("real newlines", "stay literal", "Empty skips", "set_comment")),
        ("create_memory_block", "initialized", ("forced true", "268435456", "false for larger")),
        ("create_memory_block", "bytes_hex", ("16777216 decoded bytes", "initialized=true", "excludes bytes_base64")),
        ("disassemble_bytes", "length", ("end_address takes precedence", "Default 0", "100 bytes")),
        ("emulate_function", "read_memory_after", ("after execution", "Required to see mutations", "original program bytes")),
        ("search_strings", "encoding", ("NOT a filter", "all defined strings", "ascii")),
        ("set_function_no_return", "no_return", ("Required; no default", "CALL_TERMINATOR", "False restores")),
    ],
)
def test_parameter_rewrites_preserve_edge_cases(name, parameter, guidance):
    recording = Path(__file__).resolve().parents[1] / "conformance/snapshots/mcp_schema.snap"
    tools = schema._parse_schema(json.loads(recording.read_text(encoding="utf-8")))
    original = next(t for t in tools if t["name"] == name)["input_schema"]
    compact = schema._compact_input_schema(original)
    published = compact["properties"][parameter]["description"]
    assert len(published) < len(original["properties"][parameter]["description"])
    for phrase in guidance:
        assert phrase in published
