# Schema benchmark — 2026-10-18, refreshed capture

The latest conversation at physical lines **173–174** contains **206 Ghidra
tools**, plus 13 client tools (219 total). The Ghidra schema measures **149,684
normalized JSON characters / 149,734 UTF-8 bytes**. Both requests contain the
same tool array. Applying today's production compactor and disabled-name filter
changes nothing: the fresh capture already includes the current trimming rules.
No bridge runtime behavior was changed for this analysis.

[SCHEMA_CURRENT_2026-10-18.json](SCHEMA_CURRENT_2026-10-18.json) now exports the
actual latest Ghidra tool array. Its indentation is for inspection; measurements
use `json.dumps(..., ensure_ascii=False)` with default separators.
[SCHEMA_BENCHMARK_2026-10-18.json](SCHEMA_BENCHMARK_2026-10-18.json) contains the
recomputed machine-readable measurements and experimental sizes.

## Current schema and historical comparison

The 206 tools include three static bridge tools (`list_instances`,
`connect_instance`, `import_file`) and 203 dynamic tools. Compared with the
previously analyzed, republished 190-tool set, all 16 added tools are Ghidra
TraceRmi debugger tools. They contribute 5,646 characters including array
separators; changes to three shared tools contribute another 97. That explains
the entire 5,743-character increase from 143,941. External WinDbg debugger
proxies are a separate feature.

There are **735 advertised parameters**, **184 required entries**, 127 parameter
`anyOf` nodes, and 551 parameter default annotations. Tool descriptions contain
25,378 text characters and parameter descriptions 43,834: **69,212 characters,
46.24%** of the schema before JSON annotation/escaping overhead. Aliases,
defaults, validation constraints and nullable unions remain advertised.

Only four tools advertise `dry_run`, all declared by the saved server metadata:
`archive_ingest_function`, `archive_ingest_program`, `checkin_program`, and
`merge_program_documentation`. No metadata-confirmed synthetic dry-run inputs
remain, so the existing opt-out offers **zero further savings on this capture**.

| Captured request | Ghidra tools | Schema characters | Whole-request input tokens |
| --- | ---: | ---: | ---: |
| Line 164, older fresh request | 191 | 174,050 | 46,217 |
| Line 171, intermediate fresh request | 190 | 153,803 | 41,678 |
| Line 173, latest fresh request | 206 | 149,684 | 40,991 |

These three requests each have one system and one user message. The latest
schema is 24,366 characters smaller than line 164 (14.00%), despite 15 more
tools. Whole-request input usage is 5,226 tokens lower (11.31%); it includes
messages and non-Ghidra tools, so it is **not isolated schema token savings**.
Line 174 has the same schema but more conversation history and 41,130 input
tokens; use line 173 for the fresh-request usage observation.

## Further trims, measured against the latest 149,684 characters

Every experiment below retains **all 206 tools**. None has been applied to the
bridge. Alias and required-field matching uses the saved upstream snapshot;
production publication should use metadata from the connected server.

| Experiment | Result characters | Saved | Reduction |
| --- | ---: | ---: | ---: |
| Publish canonical arguments only | 141,762 | 7,922 | 5.29% |
| Compact simple nullable unions | 147,038 | 2,646 | 1.77% |
| Omit `default: null` annotations | 147,525 | 2,159 | 1.44% |
| Canonical arguments + nullable unions | 141,216 | 8,468 | 5.66% |
| Both + omit null defaults | 140,774 | 8,910 | 5.95% |

**The savings overlap.** Removing 101 aliases also removes 100 simple nullable
unions. Compacting unions afterward saves only another 546 characters. The
canonical-only experiment restores 21 required canonical inputs. A production
implementation should preserve aliases in the internal argument model/dispatch
for existing callers and restore required fields only in the published copy.
The metadata check found no aliases colliding with canonical parameters in this
capture.

Canonical-only publication is the largest measured structural opportunity.
Nullable type arrays need verification through the actual client's converter;
constrained branches and sibling `type` declarations are preserved by this
experiment. Omitting null defaults is lower priority because it can change
client-side default handling even when internal defaults remain intact.

For further manual description rewriting, start with:

| Tool | Total schema characters | Parameter-description text |
| --- | ---: | ---: |
| `apply_documentation` | 4,197 | 2,147 |
| `create_memory_block` | 2,794 | 1,565 |
| `get_functions` | 2,446 | 1,058 |
| `find_functions` | 2,314 | 845 |

Preserve formats, limits, precedence and failure behavior. The same address
syntax appears 40 times (2,480 text characters), so another concise exact rewrite
is a smaller opportunity. Removing every description would save 82,645
characters including annotation overhead, but is only a lower bound because it
discards call guidance. No automatic truncation is proposed.

Compact JSON separators save 7,314 serialized characters; that is a client
serializer choice, not a schema change or guaranteed reduction in model context.
Category omission costs are in the JSON report, but omitting tools is outside
the current all-206-tools comparison. Pagination does not help context if the
client eventually loads every page. Existing lazy-load helpers are disabled.

## Separate offline catalog replay

The saved Java catalog contains 205 endpoints. Today's registry publishes 206
tools from it: disabled `clear_flow_and_repair` and static-owned `import_file`
leave 203 dynamic registrations, plus three statics. This replay uses saved Java
metadata and cannot replace the fresh client capture above.

| Synthetic `dry_run` setting | Function-array characters | MCP tool-array characters | `dry_run` inputs |
| --- | ---: | ---: | ---: |
| Off (`0`) | 149,654 | 154,887 | 4 |
| On (`1`, default) | 157,144 | 162,377 | 104 |

The offline synthetic-input opt-out saves 7,490 characters. That saving is
already absent from the latest capture and must not be added to its scenarios.
The replay's function-array projection differs from the actual capture by 30
characters, further demonstrating why the actual request is the baseline.
The separate MCP-array metric includes SDK annotations and uses a different
representation from the captured function array.

## Reproduce and validate

```sh
.venv/bin/python tools/context_analysis/benchmark_schema_options.py \
  2026-10-18-analysis.jsonl --replay-catalog \
  --schema-output SCHEMA_CURRENT_2026-10-18.json \
  > SCHEMA_BENCHMARK_2026-10-18.json
```

The last nonempty request tools array is selected (currently line 174).
`--line 173` selects the latest fresh request with the identical schema.
`--prefix` supports other client prefixes; `--catalog` supplies alternate
upstream alias/category metadata. The script emits schemas and aggregate
measurements, never logged messages, headers or tool results. It does not
contact Ghidra, call a model or access the external network.

Validation: **42 focused tests passed**. Additional checks against the updated
capture verified exact compaction idempotence, 206 unique tool names, identical
schemas at lines 173–174, all experimental sizes and unchanged tool counts.
No Java build was needed. No production trims were applied.

Remaining: select a publication change. Canonical-only publication offers the
largest measured structural saving; union/default changes require actual-client
validation. Exact schema token savings require tokenizer/provider isolation.
