"""Measure actual request schemas without treating request usage as schema tokens.

Run from the repository root:
  python tools/context_analysis/analyze_request_log.py 2026-10-18-analysis.jsonl

Uses only the standard library. Character counts use json.dumps with
ensure_ascii=False and its default separators, consistently across variants.
No logged prompts, headers, credentials, or tool results are printed.
"""

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path


def characters(value):
    return len(json.dumps(value, ensure_ascii=False))


def ghidra_tools(tools):
    return [t for t in tools if t["function"]["name"].startswith("ghidra_")]


def describe(tools):
    functions = [t["function"] for t in ghidra_tools(tools)]
    params = [p for f in functions for p in f["parameters"]["properties"].values()]
    return {
        "tools": len(tools),
        "ghidra_tools": len(functions),
        "ghidra_characters": characters(ghidra_tools(tools)),
        "tool_description_characters": sum(len(f.get("description", "")) for f in functions),
        "parameter_description_characters": sum(len(p.get("description", "")) for p in params),
        "parameters": len(params),
        "parameter_keys": dict(Counter(k for p in params for k in p)),
    }


def compact_schema(schema, *, empty=False, unions=False):
    """Visit schema nodes only; defaults/examples/enum objects are literal data."""
    result = deepcopy(schema)
    if empty and result.get("description") == "":
        del result["description"]
    alternatives = result.get("anyOf")
    if unions and isinstance(alternatives, list) and alternatives and all(
        isinstance(v, dict) and set(v) == {"type"} and isinstance(v["type"], str)
        for v in alternatives
    ):
        result["type"] = [v["type"] for v in result.pop("anyOf")]
    for key in ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas"):
        if isinstance(result.get(key), dict):
            result[key] = {
                name: compact_schema(value, empty=empty, unions=unions)
                if isinstance(value, dict) else value
                for name, value in result[key].items()
            }
    for key in (
        "items", "additionalItems", "additionalProperties", "unevaluatedProperties",
        "unevaluatedItems", "contains", "propertyNames", "not", "if", "then", "else",
        "contentSchema", "allOf", "anyOf", "oneOf", "prefixItems",
    ):
        value = result.get(key)
        if isinstance(value, dict):
            result[key] = compact_schema(value, empty=empty, unions=unions)
        elif isinstance(value, list):
            result[key] = [
                compact_schema(v, empty=empty, unions=unions) if isinstance(v, dict) else v
                for v in value
            ]
    return result


def scenarios(tools, catalog):
    tools = deepcopy(ghidra_tools(tools))
    baseline = characters(tools)
    results = []

    def record(label, candidate):
        results.append({
            "scenario": label, "characters": characters(candidate),
            "saved_characters": baseline - characters(candidate),
        })

    record("recorded", tools)
    for label, unions in (("remove_empty_descriptions", False), ("also_compact_simple_unions", True)):
        for tool in tools:
            function = tool["function"]
            function["parameters"] = compact_schema(function["parameters"], empty=True, unions=unions)
        record(label, tools)

    lookup = {t["function"]["name"]: t["function"] for t in tools}
    aliases_removed = required_restored = 0
    for upstream in catalog["tools"]:
        function = lookup.get("ghidra_" + (upstream.get("name") or upstream["path"].lstrip("/")))
        if function is None:
            continue
        schema = function["parameters"]
        for param in upstream["params"]:
            removed = False
            for alias in param.get("aliases", []):
                if alias in schema["properties"]:
                    del schema["properties"][alias]
                    aliases_removed += 1
                    removed = True
            if removed and param.get("required") and param["name"] not in schema.get("required", []):
                schema.setdefault("required", []).append(param["name"])
                required_restored += 1
    record("also_advertise_canonical_arguments_only", tools)
    for tool_budget, param_budget in ((240, 160), (200, 120), (160, 100)):
        candidate = deepcopy(tools)
        for tool in candidate:
            function = tool["function"]
            function["description"] = function.get("description", "")[:tool_budget]
            for param in function["parameters"]["properties"].values():
                if "description" in param:
                    param["description"] = param["description"][:param_budget]
        record(f"SIMULATION_ONLY_description_budgets_{tool_budget}_{param_budget}", candidate)
    return {"aliases_confirmed": aliases_removed, "required_restored": required_restored, "cumulative": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--catalog", type=Path, default=Path(__file__).resolve().parents[2] / "tests/conformance/snapshots/mcp_schema.snap")
    args = parser.parse_args()
    variants = {}
    row_count = 0
    latest_tools = []
    with args.log.open(encoding="utf-8") as source:
        for row_count, line in enumerate(source, 1):
            row = json.loads(line)
            tools = (row.get("request_body") or {}).get("tools", [])
            digest = hashlib.sha256(json.dumps(tools, sort_keys=True).encode()).hexdigest()[:10]
            if digest not in variants:
                variants[digest] = {
                    "first_line": row_count, "first_timestamp_as_logged": row.get("ts"),
                    "first_request_usage": row.get("usage"), **describe(tools), "requests": 0,
                }
            variants[digest]["requests"] += 1
            variants[digest]["last_line"] = row_count
            latest_tools = tools
    print(json.dumps({
        "rows": row_count, "measurement": "normalized JSON characters; usage.in is whole-request tokens",
        "variants": list(variants.values()),
        "latest_schema_scenarios": scenarios(latest_tools, json.loads(args.catalog.read_text(encoding="utf-8"))),
        "longest_latest_ghidra_tools": [
            {"name": t["function"]["name"], "characters": characters(t)}
            for t in sorted(ghidra_tools(latest_tools), key=characters, reverse=True)[:10]
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
