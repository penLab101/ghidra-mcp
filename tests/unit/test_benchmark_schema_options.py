"""Keep exploratory measurements honest about contracts and overlapping savings."""

from copy import deepcopy

from tools.context_analysis.benchmark_schema_options import benchmark, transform
from tools.context_analysis.measure_schema_trim import metrics


def fixture():
    literal = {"description": "literal guidance", "default": None,
               "anyOf": [{"type": "string"}, {"type": "null"}]}
    nullable = {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None}
    tools = [{"type": "function", "function": {
        "name": "custom_probe", "description": "Keep guidance.", "parameters": {
            "type": "object", "properties": {
                "canonical": deepcopy(nullable), "old_name": deepcopy(nullable),
                "object": {"type": "object", "default": literal, "examples": [literal]},
                "constrained": {"anyOf": [{"type": "string", "minLength": 2}, {"type": "null"}]},
                "sibling_type": {"type": "string", **deepcopy(nullable)},
            }, "required": ["object"],
        },
    }}]
    metadata = {"probe": {"input_schema": {
        "properties": {"canonical": {"aliases": ["old_name", "object"]}, "object": {}},
        "required": ["canonical", "object"],
    }}}
    return tools, metadata


def test_experiments_keep_literals_constraints_and_restore_canonical_required():
    tools, metadata = fixture()
    before = deepcopy(tools)
    candidate, changes = transform(tools, metadata, "custom_", aliases=True, unions=True,
                                   null_defaults=True, descriptions=True)
    params = candidate[0]["function"]["parameters"]
    assert params["required"] == ["object", "canonical"]
    assert "old_name" not in params["properties"]
    assert params["properties"]["canonical"] == {"type": ["string", "null"]}
    assert params["properties"]["object"] == before[0]["function"]["parameters"]["properties"]["object"]
    assert params["properties"]["constrained"] == before[0]["function"]["parameters"]["properties"]["constrained"]
    assert params["properties"]["sibling_type"]["type"] == "string"
    assert "anyOf" in params["properties"]["sibling_type"]
    assert changes["aliases_removed"] == changes["canonical_required_restored"] == 1
    assert tools == before


def test_combined_savings_do_not_double_count_alias_unions():
    tools, metadata = fixture()
    aliases, _ = transform(tools, metadata, "custom_", aliases=True)
    unions, _ = transform(tools, metadata, "custom_", unions=True)
    combined, changes = transform(tools, metadata, "custom_", aliases=True, unions=True)
    size = lambda value: metrics(value)["characters"]
    assert size(tools) - size(combined) < (size(tools) - size(aliases)) + (size(tools) - size(unions))
    assert changes["nullable_unions_compacted"] == 1


def test_report_uses_current_compaction_and_filters_with_custom_prefix():
    tools, _ = fixture()
    tools[0]["function"]["parameters"]["title"] = "Discard schema title"
    disabled = deepcopy(tools[0])
    disabled["function"]["name"] = "custom_clear_flow_and_repair"
    tools.append(disabled)
    before = deepcopy(tools)
    catalog = {"tools": [{"path": "/probe", "category": "function", "params": [
        {"name": "canonical", "type": "string", "required": True, "aliases": ["old_name"]},
    ]}]}
    report, current = benchmark(tools, catalog, "custom_")
    assert report["current_capture_republication"]["after_disabled_tool_filter"]["tools"] == 1
    assert "title" not in current[0]["function"]["parameters"]
    assert report["current_shape"]["parameters"] == 5
    experiment = report["experiments_independent_unless_named_combined"][0]
    assert experiment["changes"] == {"aliases_removed": 1, "canonical_required_restored": 1}
    assert report["category_omission_costs"][0]["category"] == "function"
    assert tools == before
