"""Keep tools/list lean without changing the callable contract."""

import asyncio
from copy import deepcopy
import json
from pathlib import Path

from mcp import types
from mcp.server.fastmcp.exceptions import ToolError
import pytest

from bridge_mcp_ghidra import registry, schema, server, state


def test_schema_compaction_preserves_arguments_constraints_and_literal_data():
    original = {
        "title": "Arguments",
        "type": "object",
        "required": ["title"],
        "properties": {
            "title": {"title": "Title", "type": "string", "minLength": 1},
            "values": {
                "title": "Values",
                "anyOf": [
                    {"type": "array", "items": {"$ref": "#/$defs/Entry", "title": "Item"}},
                    {"type": "null"},
                ],
                "default": None,
            },
        },
        "$defs": {
            "Entry": {
                "title": "Entry",
                "type": "object",
                "properties": {"title": {"title": "Label", "type": "string"}},
                "additionalProperties": False,
                "default": {"title": "literal title"},
                "examples": [{"title": "example title"}],
                "enum": [{"title": "enum title"}],
            },
        },
        "additionalProperties": False,
    }
    before = deepcopy(original)
    expected = deepcopy(original)
    del expected["title"]
    del expected["properties"]["title"]["title"]
    del expected["properties"]["values"]["title"]
    del expected["properties"]["values"]["anyOf"][0]["items"]["title"]
    del expected["$defs"]["Entry"]["title"]
    del expected["$defs"]["Entry"]["properties"]["title"]["title"]

    assert schema._compact_input_schema(original) == expected
    assert original == before


def test_only_known_boilerplate_is_shortened():
    verbose, concise = schema._DESCRIPTION_REPLACEMENTS[0]
    original = {
        "description": f"Address filter (omit to return all addresses). {verbose}",
        "properties": {
            "program": {"description": "Program name (omit for all open programs)"},
            "address": {"description": "Trace address; never a static program address."},
            "dry_run": {"description": "Count what would be merged without writing."},
        },
    }
    compact = schema._compact_input_schema(original)
    assert compact["description"] == f"Address filter (omit to return all addresses). {concise}"
    assert compact["properties"] == original["properties"]
    assert schema._compact_input_schema(compact) == compact


def test_empty_descriptions_removed_only_from_schema_nodes():
    literal = {"description": "", "title": "literal"}
    original = {
        "description": "",
        "properties": {
            "description": {"type": "string", "description": " \n\t"},
            "program": {
                "type": "string",
                "description": "Target program name (omit to use the active program)",
                "default": "",
            },
            "entries": {
                "anyOf": [
                    {"type": "array", "items": {"type": "object", "description": ""}},
                    {"type": "null", "description": ""},
                ],
                "default": None,
            },
        },
        "$defs": {"Entry": {"type": "string", "description": ""}},
        "additionalProperties": {"type": "string", "description": ""},
        "default": literal,
        "enum": [literal],
        "examples": [literal],
    }
    before = deepcopy(original)
    compact = schema._compact_input_schema(original)
    assert "description" not in compact
    assert compact["properties"]["description"] == {"type": "string"}
    assert compact["properties"]["program"] == {"type": "string", "default": ""}
    assert compact["properties"]["entries"] == {
        "anyOf": [{"type": "array", "items": {"type": "object"}}, {"type": "null"}],
        "default": None,
    }
    assert compact["$defs"]["Entry"] == {"type": "string"}
    assert compact["additionalProperties"] == {"type": "string"}
    for key in ("default", "enum", "examples"):
        assert compact[key] == original[key]
    assert schema._compact_input_schema(compact) == compact
    assert original == before


def test_pagination_compaction_preserves_tool_specific_zero_limit_rules():
    recording = Path(__file__).resolve().parents[1] / "conformance/snapshots/mcp_schema.snap"
    tools = schema._parse_schema(json.loads(recording.read_text(encoding="utf-8")))
    compacted = 0
    for tool in tools:
        original = tool["input_schema"]
        compact = schema._compact_input_schema(original)
        for name in ("offset", "limit"):
            param = original["properties"].get(name)
            if not param or "description" not in param:
                continue
            description = param["description"]
            published = compact["properties"][name]["description"]
            if "EMPTY page" in description or "MINIMUM of 1" in description:
                # Some endpoints interpret zero as empty or one, not unlimited.
                assert published == description
            # An offset can also be a struct byte offset or a filtered hash
            # offset. This check concerns the shared pagination boilerplate.
            if name == "offset" and "Page by adding `limit`" not in description:
                continue
            if name == "limit" and not (
                "negative value for no limit" in description or "0 means no limit" in description
            ):
                continue
            if published != description:
                compacted += 1
                assert len(published) < len(description)
                if name == "offset":
                    assert "`limit`" in published and "`total`" in published
                elif "negative value for no limit" in description:
                    assert "<=0 = unlimited" in published and "`total`" in published
                else:
                    assert "0 = unlimited" in published
            assert compact["properties"][name].get("default") == param.get("default")
    assert compacted >= 16


@pytest.fixture
def isolated_tools(monkeypatch):
    monkeypatch.setattr(server.mcp._tool_manager, "_tools", {})
    monkeypatch.setattr(server.mcp._mcp_server, "_tool_cache", {})
    monkeypatch.setattr(state, "_dynamic_tool_names", [])
    # Pagination replaces this handler; restore it after each test.
    monkeypatch.setattr(
        server.mcp._mcp_server,
        "request_handlers",
        dict(server.mcp._mcp_server.request_handlers),
    )


def _list_from_protocol(cursor=None):
    handler = server.mcp._mcp_server.request_handlers[types.ListToolsRequest]
    params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
    return asyncio.run(handler(types.ListToolsRequest(method="tools/list", params=params))).root


@pytest.mark.parametrize("synthetic_dry_run", ["0", "1"])
@pytest.mark.parametrize("paginated", [False, True])
def test_wire_schema_is_compact_for_static_and_late_dynamic_tools(
    isolated_tools, monkeypatch, paginated, synthetic_dry_run,
):
    monkeypatch.setenv("GHIDRA_MCP_SYNTHETIC_DRY_RUN", synthetic_dry_run)
    description, compact_description = schema._DESCRIPTION_REPLACEMENTS[-1]

    def static_probe(title: str, limit: int = 10) -> str:
        return title

    server.mcp.add_tool(
        static_probe, name="aaa_static", description=description, structured_output=False,
    )
    if paginated:
        server.enable_tool_pagination(1)
    first = _list_from_protocol()
    assert "title" in first.tools[0].inputSchema["properties"]
    assert "title" not in first.tools[0].inputSchema["properties"]["title"]
    assert first.tools[0].inputSchema["properties"]["limit"]["default"] == 10
    assert first.tools[0].description == compact_description
    assert server.mcp._tool_manager._tools["aaa_static"].description == description

    suffix = " Full tool-specific documentation remains available."
    description += suffix
    verbose, concise = schema._DESCRIPTION_REPLACEMENTS[0]
    registry._register_tool_def(
        {
            "name": "zzz_dynamic",
            "endpoint": "/probe",
            "http_method": "POST",
            "description": description,
            "read_only": False,
            "input_schema": {
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": {"type": "string", "description": verbose, "aliases": ["old_address"]},
                    "program": {
                        "type": "string",
                        "description": "Target program name (omit to use the active program)",
                    },
                },
            },
        }
    )
    first = _list_from_protocol()
    tools = first.tools + (_list_from_protocol(first.nextCursor).tools if first.nextCursor else [])
    assert [tool.name for tool in tools] == ["aaa_static", "zzz_dynamic"]
    dynamic = tools[-1]
    assert dynamic.inputSchema["properties"]["address"]["description"] == concise
    assert "description" not in dynamic.inputSchema["properties"]["program"]
    assert dynamic.inputSchema["required"] == ["address"]
    assert "old_address" not in dynamic.inputSchema["properties"]
    if synthetic_dry_run == "1":
        assert dynamic.inputSchema["properties"]["dry_run"]["default"] is False
    else:
        assert "dry_run" not in dynamic.inputSchema["properties"]
    assert dynamic.description == compact_description + suffix
    assert dynamic.annotations.readOnlyHint is False
    assert dynamic.outputSchema is None
    # Publication must not alter the SDK schema or its argument model.
    stored = server.mcp._tool_manager._tools["zzz_dynamic"]
    assert stored.description == description
    assert stored.parameters["properties"]["address"]["description"] == verbose
    assert stored.parameters["properties"]["program"]["description"] == (
        "Target program name (omit to use the active program)"
    )
    assert "title" in stored.parameters["properties"]["address"]
    assert "old_address" in stored.parameters["properties"]
    assert "address" not in stored.parameters.get("required", [])


def test_compact_tool_still_validates_and_dispatches_defaults_and_aliases(isolated_tools, monkeypatch):
    calls = []

    def post(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        return '{"success": true}'

    monkeypatch.setattr(registry.dispatch, "dispatch_post", post)
    registry._register_tool_def(
        {
            "name": "write_probe",
            "endpoint": "/write_probe",
            "http_method": "POST",
            "input_schema": {
                "type": "object",
                "required": ["name", "count"],
                "properties": {
                    "name": {"type": "string", "aliases": ["old_name"]},
                    "count": {"type": "integer"},
                    "limit": {"type": "integer", "default": 10},
                },
            },
        }
    )
    advertised = _list_from_protocol().tools[0]
    assert advertised.inputSchema["required"] == ["count", "name"]
    assert "old_name" not in advertised.inputSchema["properties"]
    # Exercise the wire handler after tools/list populated the SDK's cache.
    handler = server.mcp._mcp_server.request_handlers[types.CallToolRequest]

    def call(arguments):
        return asyncio.run(handler(types.CallToolRequest(
            method="tools/call", params=types.CallToolRequestParams(name="write_probe", arguments=arguments),
        ))).root

    assert not call({"old_name": "Example", "count": 2, "dry_run": True}).isError
    assert calls == [
        (
            "/write_probe",
            {
                "data": {"name": "Example", "count": 2, "limit": 10},
                "query_params": {"dry_run": "true"},
            },
        )
    ]
    with pytest.raises(ToolError, match="count"):
        asyncio.run(server.mcp.call_tool("write_probe", {"old_name": "Example"}))
    assert call({"count": 2}).isError
    assert len(calls) == 1
    assert not call({"name": "Canonical", "old_name": "Ignored", "count": 3}).isError
    assert calls[-1][1]["data"]["name"] == "Canonical"


def test_canonical_publication_respects_collisions_and_tool_lifecycle(isolated_tools):
    definition = {
        "name": "collision_probe", "endpoint": "/probe",
        "input_schema": {
            "required": ["first", "second", "real"],
            "properties": {
                "first": {"type": "string", "aliases": ["shared", "real"]},
                "second": {"type": "string", "aliases": ["shared"]},
                "real": {"type": "string"},
                "optional": {"type": "integer", "aliases": ["old_optional"]},
            },
        },
    }
    before = deepcopy(definition)
    registry._register_tool_def(definition)
    published = _list_from_protocol().tools[0].inputSchema
    assert set(published["properties"]) == {"first", "second", "real", "optional"}
    assert set(published["required"]) == {"first", "second", "real"}
    assert published["properties"]["optional"] == {
        "anyOf": [{"type": "integer"}, {"type": "null"}], "default": None,
    }
    assert _list_from_protocol().tools[0].inputSchema == published
    assert definition == before
    # A replacement must use its own metadata, even when an old alias is now a
    # real argument. A subsequent static replacement has no dynamic metadata.
    server.mcp.remove_tool("collision_probe")
    replacement = deepcopy(definition)
    replacement["input_schema"] = {
        "required": ["shared"], "properties": {"shared": {"type": "string"}},
    }
    registry._register_tool_def(replacement)
    assert _list_from_protocol().tools[0].inputSchema == {
        "type": "object", "required": ["shared"], "properties": {"shared": {"type": "string"}},
    }
    server.mcp.remove_tool("collision_probe")

    def static_probe(old_optional: str):
        return old_optional

    server.mcp.add_tool(static_probe, name="collision_probe", structured_output=False)
    assert _list_from_protocol().tools[0].inputSchema["required"] == ["old_optional"]


def test_recorded_catalog_payload_shrinks_without_losing_contract(isolated_tools):
    recording = Path(__file__).resolve().parents[1] / "conformance/snapshots/mcp_schema.snap"
    definitions = schema._parse_schema(json.loads(recording.read_text(encoding="utf-8")))
    metadata = {tool["name"]: tool["input_schema"] for tool in definitions}
    for tool in definitions:
        registry._register_tool_def(tool)  # import_file is owned by the static bridge tool.
    raw = asyncio.run(server._orig_list_tools())
    compact = asyncio.run(server.mcp.list_tools())

    def size(tools):
        return len(json.dumps([t.model_dump(mode="json", exclude_none=True) for t in tools]).encode())

    assert len(raw) == len(compact)
    assert {tool.name for tool in compact} == (
        metadata.keys() - schema.DISABLED_TOOL_NAMES - schema.STATIC_TOOL_NAMES
    )
    assert size(compact) < size(raw) * 0.82
    for before, after in zip(raw, compact):
        assert after.model_dump(exclude={"inputSchema", "description"}) == before.model_dump(
            exclude={"inputSchema", "description"}
        )
        assert after.description == (
            schema._compact_description(before.description) if before.description is not None else None
        )
        definition = metadata[before.name]
        assert after.inputSchema["properties"].keys() == definition["properties"].keys() | (
            {"dry_run"} if "dry_run" in before.inputSchema["properties"] else set()
        )
        assert set(after.inputSchema.get("required", [])) == set(before.inputSchema.get("required", [])) | {
            name for name in definition.get("required", [])
            if definition["properties"][name].get("aliases")
        }
        for name, original_param in before.inputSchema["properties"].items():
            if name not in after.inputSchema["properties"]:
                assert any(name in param.get("aliases", []) for param in definition["properties"].values())
                continue
            # All validation keywords, defaults and nullable unions must match.
            published_param = after.inputSchema["properties"][name]
            assert {k: v for k, v in original_param.items() if k not in {"title", "description"}} == {
                k: v for k, v in published_param.items() if k not in {"title", "description"}
            }
