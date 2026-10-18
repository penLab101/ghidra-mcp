## Measure the current trim against a captured schema

```sh
.venv/bin/python tools/context_analysis/measure_schema_trim.py 2026-10-18-analysis.jsonl
# Select a particular physical JSONL line instead of the last nonempty tool array:
.venv/bin/python tools/context_analysis/measure_schema_trim.py 2026-10-18-analysis.jsonl --line 164
```

`measure_schema_trim.py` treats the captured `request_body.tools` array as the
previous conversation's baseline. It imports the current production rules from
`schema.py`, then reports baseline size, size after compaction, and size after
filtering disabled tools. Character and UTF-8 byte savings are measured with
consistent JSON normalization; they are not token counts or original HTTP sizes.
It measures only function tools beginning with `ghidra_`; use `--prefix` for a
different client prefix (or `--prefix ''` for unprefixed names).

The script requires the normal bridge dependencies and does not contact Ghidra.
Its JSON output contains aggregate measurements and removed tool names, without
logged messages, headers or results. Redirect stdout to save a report.

On the final schema in `2026-10-18-analysis.jsonl`: **174,050 → 146,164 → 143,941
characters** (compaction saves 27,886; disabled-tool filtering saves another
2,223; total reduction **17.30%**, 191 → 190 Ghidra tools). Curated rewrites of
36 verbose tool descriptions and 23 parameter descriptions in
`python/bridge_mcp_ghidra/schema_descriptions.py` feed the existing
`schema.py` replacement path. That first pass reached 153,706 characters.
The same `schema_descriptions.py` table now further shortens 22 tool
descriptions, 49 parameter descriptions and repeated address-space guidance,
saving another 9,765 characters (6.35% of the previous result). Unknown
descriptions pass through; there is no automatic truncation.

Other measured opportunities on the currently compacted capture, evaluated
independently and **not implemented**:

- Publishing only canonical argument names: 7,922 characters for 101
  metadata-confirmed aliases, after restoring 21 canonical required entries.
  Keep aliases in the internal callable signature/dispatch so older callers
  continue to work; derive publication changes from server metadata.
- Compact simple nullable `anyOf` branches into a type array: 2,646 characters.
  Needs compatibility checks with the actual MCP client/provider.
- The existing `GHIDRA_MCP_SYNTHETIC_DRY_RUN=0` flag can reduce newly registered
  schemas. This capture already has no metadata-confirmed synthetic dry-run
  inputs left to remove, so it offers no further savings in this comparison.

These are normalized character savings, not measured tokens. Further large
reductions would require publishing fewer tools; with lazy-load management
helpers disabled, a lazy subset cannot expand through those MCP tools. Tool-list
pagination alone does not reduce context if the client fetches every page.

The older catalog-based scripts below estimate a different schema; their token
figures should not be used as measured savings for captured requests.

