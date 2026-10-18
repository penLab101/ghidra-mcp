"""Measure current schema.py trimming against a captured request's tool array.

Run from the repository root:
  .venv/bin/python tools/context_analysis/measure_schema_trim.py REQUEST_LOG.jsonl

Uses the last nonempty request_body.tools array by default, or --line N to
select a physical JSONL line. Only matching tool schemas are measured; logged
messages, headers and results are never emitted. Requires the bridge's normal
Python dependencies. No live Ghidra instance or tokenizer is needed.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

# Support direct execution without requiring an editable package installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
from bridge_mcp_ghidra import schema  # noqa: E402


def load_tools(path: Path, line: int | None = None) -> tuple[list[dict], int]:
    """Select a captured tools array without retaining whole request bodies."""
    if line is not None and line < 1:
        raise ValueError("--line must be a positive physical line number")
    selected = None
    with path.open(encoding="utf-8") as source:
        for number, text in enumerate(source, 1):
            if line is not None and number != line:
                continue
            if not text.strip():
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {number}: {exc.msg}") from exc
            body = row.get("request_body") if isinstance(row, dict) else None
            tools = body.get("tools") if isinstance(body, dict) else None
            if isinstance(tools, list) and tools:
                selected = tools, number
            if line is not None:
                break
    if selected is None:
        location = f" at line {line}" if line is not None else ""
        raise ValueError(f"No nonempty request_body.tools array found{location}")
    return selected


def metrics(tools: list[dict]) -> dict:
    # Match the earlier analysis's normalization, including default separators.
    serialized = json.dumps(tools, ensure_ascii=False)
    return {
        "tools": len(tools),
        "characters": len(serialized),
        "utf8_bytes": len(serialized.encode("utf-8")),
    }


def measure_trim(tools: list[dict], prefix: str = "ghidra_") -> dict:
    """Apply production compaction and disabled names to a copy of the baseline."""
    baseline = [
        tool for tool in tools
        if tool.get("type") == "function"
        and tool.get("function", {}).get("name", "").startswith(prefix)
    ]
    if not baseline:
        raise ValueError("No function tools match the selected prefix")
    compacted = deepcopy(baseline)
    for tool in compacted:
        function = tool["function"]
        if isinstance(function.get("description"), str):
            function["description"] = schema._compact_description(function["description"])
        function["parameters"] = schema._compact_input_schema(function["parameters"])

    removed = [
        tool["function"]["name"] for tool in compacted
        if tool["function"]["name"][len(prefix):] in schema.DISABLED_TOOL_NAMES
    ]
    removed_names = set(removed)
    enabled = [tool for tool in compacted if tool["function"]["name"] not in removed_names]
    before = metrics(baseline)

    def stage(candidate):
        result = metrics(candidate)
        result["saved_characters"] = before["characters"] - result["characters"]
        result["saved_utf8_bytes"] = before["utf8_bytes"] - result["utf8_bytes"]
        result["character_reduction_percent"] = round(
            100 * result["saved_characters"] / before["characters"], 2,
        )
        return result

    return {
        "measurement": "Normalized JSON (ensure_ascii=False, default separators); not token counts.",
        "assumption": "The captured tool array is the previous conversation's baseline schema.",
        "scope": "Matching function tools only; other tools and request content are excluded.",
        "tool_prefix": prefix,
        "baseline": before,
        "after_current_compaction": stage(compacted),
        "after_disabled_tool_filter": stage(enabled),
        "disabled_tools_removed": removed,
        "compaction_only_saved_characters": before["characters"] - metrics(compacted)["characters"],
        "disabled_filter_only_saved_characters": metrics(compacted)["characters"] - metrics(enabled)["characters"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Captured request JSONL file")
    parser.add_argument("--line", type=int, help="1-based physical line; default: last nonempty tool array")
    parser.add_argument("--prefix", default="ghidra_", help="Client tool-name prefix (default: ghidra_)")
    args = parser.parse_args()
    try:
        tools, line = load_tools(args.log, args.line)
        report = measure_trim(tools, args.prefix)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.error(str(exc))
    report["source_line"] = line
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
