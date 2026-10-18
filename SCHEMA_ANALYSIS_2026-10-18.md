# Schema size analysis — 2026-10-18

Yes, further trimming is possible. Most of the remaining size is documentation,
not JSON Schema scaffolding. The log's smallest full-catalog fresh request is
32,676 input tokens; the final catalog's fresh request is 46,217. Those are
whole-request token counts, not isolated schema token counts.

## Evidence and measurement

Analyzed all **170 JSONL records**, identifying **11 distinct tool arrays**.
Line numbers below refer to `2026-10-18-analysis.jsonl`. Timestamps are as logged;
the log does not specify a timezone. Ghidra characters count only functions
whose names start with `ghidra_`, using `json.dumps(..., ensure_ascii=False)`
with default separators. These normalized character counts are reproducible,
but are neither original HTTP byte counts nor tokenizer counts.

| First log line | Timestamp | All tools | Ghidra tools | Ghidra schema characters | Whole-request input tokens |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | 07:19:04 | 221 | 206 | 123,959 | 35,418 |
| 8 | 07:28:27 | 220 | 205 | 187,955 | 49,754 |
| 83 | 09:56:03 | 218 | 205 | 128,570 | 35,531 |
| 99 | 10:23:48 | 218 | 205 | 117,972 | 32,676 |
| 149 | 11:15:05 | 224 | 211 | 182,240 | 48,184 |
| 161 | 11:25:27 | 220 | 207 | 179,696 | 47,543 |
| 164 | 11:27:14 | 204 | 191 | 174,050 | 46,217 |

These rows each have just a system and user message, avoiding accumulated tool
results/history. Still, messages and non-Ghidra tools contribute to input usage.
The later rows include 13 `sys_*` tools (10,897 normalized characters), so not
all tool overhead belongs to this bridge. The log does not identify build SHAs;
the first catalog cannot conclusively be labeled the stable release.

## Why it grew after trimming

| Ghidra component | Line 1 | Line 99 | Line 164 |
| --- | ---: | ---: | ---: |
| Tool description text characters | 31,260 | 29,848 | 40,908 |
| Parameter description text characters | 0 | 17,293 | 53,157 |
| Advertised parameter properties | 762 | 666 | 720 |
| Parameter `title` annotations | 762 | 0 | 0 |
| Parameter nullable `anyOf` unions | 0 | 0 | 127 |

The initial catalog has **no parameter descriptions**. The bridge now carries
them through `Annotated[..., Field(description=...)]` in
`python/bridge_mcp_ghidra/registry.py:201`. That is useful guidance, but compares
unfavorably in size with the initial undocumented parameters.

Between lines 99 and 164, schema characters grew by **56,078**. Tool descriptions
grew by 11,060 and parameter descriptions by 35,864: documentation text alone
explains **46,924 characters, or 83.7% of the net growth**. The later catalog also
changes many tools: 65 names are added and 59 removed between lines 99 and 149.
For example, `get_functions` replaces several smaller function tools. This is
not a comparison of the same tool set before and after whitespace trimming.

The final schema has **101 confirmed compatibility aliases**. They match alias
metadata in `tests/conformance/snapshots/mcp_schema.snap`; all 101 nullable
properties without descriptions are accounted for by that metadata. The other
26 nullable properties are canonical arguments. Do not infer alias status just
from a nullable type or missing description.

## Measured further reductions

The following are **cumulative** transformations of the final Ghidra tool array.
They retain all 191 tools. No production behavior was changed for this analysis.

| Scenario | Ghidra characters | Saved vs recorded | Reduction |
| --- | ---: | ---: | ---: |
| Recorded final schema | 174,050 | 0 | 0% |
| Remove 137 empty `description` annotations | 171,447 | 2,603 | 1.5% |
| Also use compact equivalent simple union syntax | 168,801 | 5,249 | 3.0% |
| Also advertise canonical arguments only | 162,979 | 11,071 | 6.4% |
| Also budget tool descriptions to 240 chars / parameters to 160 | 143,451 | 30,599 | 17.6% |
| Instead budget descriptions to 200 / 120 chars | 135,203 | 38,847 | 22.3% |
| Instead budget descriptions to 160 / 100 chars | 127,617 | 46,433 | 26.7% |

The last three rows are **size simulations using truncation, not proposed
production truncation**. Descriptions require deliberate rewriting to retain
limits, valid values, precedence, address units, and execution requirements.
No exact token savings are claimed: this environment has no model tokenizer,
and the log exposes only whole-request usage.

Simple nullable syntax can change from
`"anyOf": [{"type": "string"}, {"type": "null"}]` to
`"type": ["string", "null"]`. This preserves JSON Schema meaning for these
simple cases. Confirm the actual MCP client's schema converter accepts this
form before deploying; do not flatten unions containing other constraints.

Canonical-only publication can leave aliases accepted by the internal argument
model and handler. It must also restore canonical required arguments in the
advertised schema: **21 required entries** need restoration in this recording.
See `registry.py:44` and `registry.py:214`; currently alias support intentionally
makes those signature arguments optional, then validates after alias folding.
Do not delete aliases from the internal model or guess their names.

## Where manual description work pays off

The final Ghidra schema contains **94,065 characters of description text**,
54.0% of its normalized size. The largest individual tools are:

| Tool | Serialized characters | Tool description | Parameter descriptions |
| --- | ---: | ---: | ---: |
| `apply_documentation` | 4,750 | 525 | 2,506 |
| `get_functions` | 3,532 | 927 | 1,471 |
| `create_memory_block` | 3,507 | 241 | 2,167 |
| `find_functions` | 2,796 | 505 | 1,030 |
| `list_globals` | 2,319 | 555 | 1,068 |

Start with migration history (`Replaces ...`), benchmark timings, repeated
explanations and verbose examples. Keep actionable constraints. For instance,
`get_functions` can explain single/bulk mode, the 20-function limit, and field
selection much more briefly while leaving field names in the parameter docs.

Repeated pagination prose is another concrete target: nine parameters repeat
the same 167-character offset explanation, and seven repeat the same
156-character limit explanation. Shorten exact known phrases while retaining
the unlimited-page convention and meaning of `total`. The already compact
62-character address syntax appears 40 times; that is less promising than
the newly verbose tool-specific descriptions.

Removing all defaults is not a recommended first step: defaults communicate
useful behavior and are explicitly preserved by current compaction tests.
Similarly, pagination does not reduce model context when a client ultimately
loads all pages. Lazy mode would reduce exposed tools, but the current local
configuration intentionally loads everything; the recommendations above work
within that choice.

## Existing disabled-tool mismatch

`schema.py:9` disables `ghidra_clear_flow_and_repair`, but registration compares
the unprefixed bridge name (`registry.py:326`). The recorded upstream schema
parses to `clear_flow_and_repair` at `/clear_flow_and_repair`, so the entry never
matches. The client supplies the `ghidra_` prefix. This explains why the final
request still includes this tool. Correcting the entry would save another
**2,240 normalized characters** by removing that tool from the recorded array.
This saving is separate from the cumulative table.

## Recommendation and reproducibility

First remove empty descriptions and verify compact nullable syntax against the
client. Then implement canonical-only *publication* with internal alias
compatibility and restored required metadata. For a material reduction beyond
6%, manually shorten the highest-cost descriptions and repeated pagination
prose. A return near the earlier 30k input range is plausible with substantial
description editing, but the measured structural changes alone will not do it.

Run from the repository root:

```sh
.venv/bin/python tools/context_analysis/analyze_request_log.py \
  2026-10-18-analysis.jsonl > SCHEMA_ANALYSIS_2026-10-18.json
```

The script uses only the standard library, emits no prompts/headers/results,
and reports variants, provider usage, schema composition, longest tools, and
cumulative scenarios. The machine-readable output is included alongside this
report. Existing `measure_context.py` / `advanced_context_analysis.py` simulate
schemas from the endpoint catalog; they omit important live details such as
parameter descriptions and aliases, so their historic token claims do not
validate this actual request size.

Validation: executed the analyzer over all 170 rows and asserted the 11-variant
count, 101 alias matches, 21 restored required entries, and recorded/canonical
scenario sizes. `git diff --check` passed. No runtime code was changed and no
live Ghidra/client/tokenizer validation was performed.
