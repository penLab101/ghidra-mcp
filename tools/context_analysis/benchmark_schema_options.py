"""Benchmark current publication and hypothetical trims, without contacting Ghidra.

Only tool schemas are emitted. Counts use the same JSON normalization as
measure_schema_trim.py; they are not provider token counts or live measurements.
"""

import argparse
import asyncio
from collections import Counter, defaultdict
from copy import deepcopy
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.context_analysis.measure_schema_trim import load_tools, measure_trim, metrics
from bridge_mcp_ghidra import config, registry, schema, server


def current_tools(tools, prefix):
    result = []
    for tool in deepcopy(tools):
        if tool.get("type") != "function":
            continue
        function = tool["function"]
        name = function["name"]
        if not name.startswith(prefix) or name[len(prefix):] in schema.DISABLED_TOOL_NAMES:
            continue
        if isinstance(function.get("description"), str):
            function["description"] = schema._compact_description(function["description"])
        function["parameters"] = schema._compact_input_schema(function["parameters"])
        result.append(tool)
    return result


def schema_nodes(node):
    """Visit schemas, never default/enum/example objects or argument-name keys."""
    yield node
    for key in ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas"):
        for value in node.get(key, {}).values():
            if isinstance(value, dict):
                yield from schema_nodes(value)
    for key in (
        "items", "additionalItems", "additionalProperties", "unevaluatedProperties",
        "unevaluatedItems", "contains", "propertyNames", "not", "if", "then", "else",
        "contentSchema", "allOf", "anyOf", "oneOf", "prefixItems",
    ):
        value = node.get(key)
        for child in value if isinstance(value, list) else [value]:
            if isinstance(child, dict):
                yield from schema_nodes(child)


def transform(tools, metadata, prefix, *, aliases=False, unions=False, null_defaults=False,
              descriptions=False):
    """Experimental advertised-copy transformations; never modify bridge state."""
    candidate = deepcopy(tools)
    counts = Counter()
    for tool in candidate:
        function = tool["function"]
        params = function["parameters"]
        definition = metadata.get(function["name"][len(prefix):], {})
        properties = params.get("properties", {})
        canonical_names = set(definition.get("input_schema", {}).get("properties", {}))
        claimed = set()
        if aliases:
            for name, param in definition.get("input_schema", {}).get("properties", {}).items():
                if name not in properties:
                    continue
                removed = False
                for alias in param.get("aliases", []):
                    if alias in canonical_names or alias in claimed:
                        continue
                    claimed.add(alias)
                    if alias in properties:
                        del properties[alias]
                        counts["aliases_removed"] += 1
                        removed = True
                if removed and name in definition["input_schema"].get("required", []):
                    required = params.setdefault("required", [])
                    if name not in required:
                        required.append(name)
                        counts["canonical_required_restored"] += 1
        if descriptions and "description" in function:
            del function["description"]
            counts["descriptions_removed"] += 1
        for node in schema_nodes(params):
            branches = node.get("anyOf")
            # Only simple nullable unions; never overwrite a sibling type.
            if unions and "type" not in node and isinstance(branches, list) and len(branches) == 2:
                if all(isinstance(b, dict) and set(b) == {"type"} and
                       isinstance(b["type"], str) for b in branches):
                    types = [b["type"] for b in branches]
                    if len(set(types)) == 2 and "null" in types:
                        node["type"] = types
                        del node["anyOf"]
                        counts["nullable_unions_compacted"] += 1
            if null_defaults and "default" in node and node["default"] is None:
                del node["default"]
                counts["null_defaults_removed"] += 1
            if descriptions and "description" in node:
                del node["description"]
                counts["descriptions_removed"] += 1
    return candidate, dict(counts)


def profile(tools):
    counts = Counter()
    keys = Counter()
    longest = []
    texts = Counter()
    for tool in tools:
        function = tool["function"]
        params = function["parameters"].get("properties", {})
        tool_chars = len(function.get("description", ""))
        param_chars = sum(len(p.get("description", "")) for p in params.values())
        counts.update(parameters=len(params), required=len(function["parameters"].get("required", [])),
                      tool_description_characters=tool_chars, parameter_description_characters=param_chars)
        for param in params.values():
            keys.update(param.keys())
            if param.get("description"):
                texts[param["description"]] += 1
        longest.append({"name": function["name"], "characters": metrics([tool])["characters"] - 2,
                        "tool_description_characters": tool_chars,
                        "parameter_description_characters": param_chars})
    return {**dict(counts), "parameter_keys": dict(keys),
            "largest_tools": sorted(longest, key=lambda t: t["characters"], reverse=True)[:15],
            "repeated_parameter_descriptions": [
                {"description": text, "occurrences": n, "text_characters": n * len(text)}
                for text, n in sorted(texts.items(), key=lambda item: item[1] * len(item[0]), reverse=True)
                if n > 1
            ][:10]}


def benchmark(tools, catalog, prefix="ghidra_"):
    current = current_tools(tools, prefix)
    baseline = metrics(current)["characters"]
    metadata = {t["name"]: t for t in schema._parse_schema(catalog)}
    experiments = []
    for label, flags in (
        ("canonical_arguments_only", {"aliases": True}),
        ("simple_nullable_type_arrays", {"unions": True}),
        ("omit_null_default_annotations", {"null_defaults": True}),
        ("canonical_and_nullable", {"aliases": True, "unions": True}),
        ("canonical_nullable_and_null_defaults", {"aliases": True, "unions": True, "null_defaults": True}),
        ("NO_GUIDANCE_lower_bound", {"descriptions": True}),
    ):
        candidate, changes = transform(current, metadata, prefix, **flags)
        size = metrics(candidate)
        experiments.append({"scenario": label, **size, "saved_characters": baseline - size["characters"],
                            "reduction_percent": round(100 * (baseline - size["characters"]) / baseline, 2),
                            "changes": changes})
    categories = defaultdict(list)
    for tool in current:
        name = tool["function"]["name"][len(prefix):]
        category = metadata.get(name, {}).get("category", "static_or_unmatched")
        categories[category].append(tool)
    group_costs = []
    for category, members in categories.items():
        remaining = [tool for tool in current if tool not in members]
        group_costs.append({"category": category, "tools": len(members),
                           "saved_characters_if_omitted": baseline - metrics(remaining)["characters"]})
    compact = json.dumps(current, ensure_ascii=False, separators=(",", ":"))
    return {
        "measurement": "Normalized JSON characters/UTF-8 bytes, not tokens; no live Ghidra connection.",
        "current_capture_republication": measure_trim(tools, prefix),
        "current_shape": profile(current),
        "experiments_independent_unless_named_combined": experiments,
        "category_omission_costs": sorted(group_costs, key=lambda g: g["saved_characters_if_omitted"], reverse=True),
        "compact_json_serialization": {"characters": len(compact), "utf8_bytes": len(compact.encode()),
                                       "saved_characters": baseline - len(compact),
                                       "note": "Serializer-only; not an MCP schema change or guaranteed context reduction."},
    }, current


def replay_catalog(catalog, prefix):
    """Exercise current SDK publication on saved Java metadata, without HTTP calls.

    Run only in the standalone CLI process: registration changes its singleton.
    """
    previous = os.environ.get("GHIDRA_MCP_SYNTHETIC_DRY_RUN")
    results = {}
    definitions = schema._parse_schema(catalog)
    try:
        for setting in ("0", "1"):
            os.environ["GHIDRA_MCP_SYNTHETIC_DRY_RUN"] = setting
            registered = registry.register_tools_from_schema(definitions)
            published = asyncio.run(server.mcp.list_tools())
            functions = [{"type": "function", "function": {
                "name": prefix + tool.name, "description": tool.description or "",
                "parameters": tool.inputSchema,
            }} for tool in published]
            results["synthetic_dry_run_" + setting] = {
                "dynamic_tools_registered": registered, "function_array": metrics(functions),
                "mcp_tool_array": metrics([t.model_dump(mode="json", exclude_none=True) for t in published]),
                "dry_run_parameters": sum("dry_run" in f["function"]["parameters"].get("properties", {})
                                          for f in functions),
            }
    finally:
        if previous is None:
            os.environ.pop("GHIDRA_MCP_SYNTHETIC_DRY_RUN", None)
        else:
            os.environ["GHIDRA_MCP_SYNTHETIC_DRY_RUN"] = previous
    return {"upstream_tools": len(definitions), "core_groups": sorted(config.CORE_GROUPS),
            "note": "Current Python bridge + saved Java snapshot; not today's live or rebuilt Java schema. "
                    "Function-array projection excludes MCP annotations; mcp_tool_array includes them.",
            "debugger_proxies_enabled": bool(config.STATIC_TOOL_NAMES & config.DEBUGGER_TOOL_NAMES),
            **results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--line", type=int)
    parser.add_argument("--prefix", default="ghidra_")
    parser.add_argument("--catalog", type=Path,
                        default=Path(__file__).resolve().parents[2] / "tests/conformance/snapshots/mcp_schema.snap")
    parser.add_argument("--replay-catalog", action="store_true")
    parser.add_argument("--schema-output", type=Path, help="Write current compacted captured tool array")
    args = parser.parse_args()
    tools, line = load_tools(args.log, args.line)
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    report, current = benchmark(tools, catalog, args.prefix)
    report["source"] = {"log": str(args.log), "line": line, "metadata_catalog": str(args.catalog)}
    if args.replay_catalog:
        report["offline_catalog_replay"] = replay_catalog(catalog, args.prefix)
    if args.schema_output:
        args.schema_output.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
