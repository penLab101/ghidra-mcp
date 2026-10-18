"""Disabled upstream tools stay out of registration and discovery."""

import asyncio
from copy import deepcopy
import json

from mcp.server.fastmcp.exceptions import ToolError
import pytest

from bridge_mcp_ghidra import registry, server, state, static_tools


@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch):
    monkeypatch.setattr(server.mcp._tool_manager, "_tools", {})
    monkeypatch.setattr(state, "_dynamic_tool_names", [])
    monkeypatch.setattr(state, "_full_schema", [])
    monkeypatch.setattr(state, "_loaded_groups", set())


def tool(name):
    return {"name": name, "endpoint": f"/{name}", "category": "function"}


@pytest.mark.parametrize("groups", [None, set()])
def test_disabled_tool_cannot_be_discovered_loaded_or_called(groups):
    disabled = "ghidra_clear_flow_and_repair"
    tools = [tool(disabled), tool("get_functions")]
    original = deepcopy(tools)

    assert registry.register_tools_from_schema(tools, groups=groups) == (1 if groups is None else 0)
    assert tools == original
    assert [td["name"] for td in state._full_schema] == ["get_functions"]
    assert registry._get_group_info()[0]["tools"] == ["get_functions"]
    assert json.loads(asyncio.run(static_tools.search_tools(disabled)))["matches"] == []
    assert json.loads(asyncio.run(static_tools.check_tools(disabled)))["results"][disabled] == {
        "status": "not_found",
    }

    registry._load_group("function")
    assert state._dynamic_tool_names == ["get_functions"]
    assert [t.name for t in asyncio.run(server.mcp.list_tools())] == ["get_functions"]
    assert registry._register_tool_def(tool(disabled)) is False
    with pytest.raises(ToolError, match="Unknown tool"):
        asyncio.run(server.mcp.call_tool(disabled, {}))


def test_changing_disabled_names_removes_and_restores_tools(monkeypatch):
    disabled_names = set()
    monkeypatch.setattr(registry, "DISABLED_TOOL_NAMES", disabled_names)
    tools = [tool("temporary_tool")]
    assert registry.register_tools_from_schema(tools) == 1

    disabled_names.add("temporary_tool")
    assert registry.register_tools_from_schema(tools) == 0
    assert "temporary_tool" not in server.mcp._tool_manager._tools
    assert state._full_schema == []

    disabled_names.clear()
    assert registry.register_tools_from_schema(tools) == 1
    assert "temporary_tool" in server.mcp._tool_manager._tools


def test_disabling_one_collision_does_not_rename_another_tool(monkeypatch):
    monkeypatch.setattr(registry, "DISABLED_TOOL_NAMES", {"foo_bar"})
    tools = [tool("foo/bar"), tool("foo_bar")]
    assert registry.register_tools_from_schema(tools) == 1
    assert state._dynamic_tool_names == ["foo_bar_2"]
    assert registry._load_group("function") == []
