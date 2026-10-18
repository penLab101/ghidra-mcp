"""Schema parsing — converts the upstream /mcp/schema to internal tool defs."""

from .config import STATIC_TOOL_NAMES, _ALL_STATIC_TOOL_NAMES
from .validation import sanitize_tool_name, _allocate_tool_name

# Temporarily hide upstream tools by their exact MCP-visible name. Add/remove
# names here, then restart the bridge. Also applies to static bridge tools.
DISABLED_TOOL_NAMES = {
    "ghidra_clear_flow_and_repair", # schema bloated + not frequently used
    # All tools are loaded up front; lazy-load management is unnecessary.
    "list_tool_groups",
    "load_tool_group",
    "unload_tool_group",
    "check_tools",
    "search_tools",
}

# Only replace known boilerplate. Tool-specific qualifications must survive;
# truncating descriptions or rewriting by parameter name can hide real rules.
_DESCRIPTION_REPLACEMENTS = (
    (
        "Accepts 0x<hex> (default space) or <space>:<hex> (e.g., mem:1000, code:ff00). "
        "Note: some programs — particularly embedded/microcontroller targets — are not "
        "address-space-agnostic; use get_address_spaces to discover spaces before "
        "assuming a plain hex address is unambiguous.",
        "0x<hex> (default space) or <address_spaces>:<hex>; (code:ff00)",
    ),
    (
        "Target program name (omit to use the active program — always specify when multiple programs are open)",
        "",
    ),
    (
        "Target program name (omit to use the active program)",
        "",
    ),
    (
        "Target program name (omit for active program).",
        "",
    ),
    (
        "Preview the change without applying it. When true the server validates the request "
        "and reports what would happen, leaving the program unmodified. Defaults to false.",
        "dryrun",
    ),
    (
        "Optional per-call override for naming enforcement: 'enforce' (reject low-quality names), "
        "'warn' (write goes through with warnings), or 'off' (skip validation entirely). "
        "Omit to use the project/global setting.",
        "Opional; Naming enforcement: 'enforce' / 'warn' / 'off'"
    ),
    (
        "Optional per-call override for naming enforcement: 'enforce' / 'warn' / 'off'. "
        "Omit to use the project/global setting.",
        "Opitonal; Naming enforcement: enforce/warn/off",
    ),
    (
        "Validate and preview without modifying the program.",
        "dryrun"
    ),
    (
        "Address in the program. ",
        ""
    ),
    (
        "Create a structure data type. Body fields must be a JSON array of objects; each object needs name and type, with optional offset. Example fields: [{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},{\"name\":\"pNext\",\"type\":\"void *\",\"offset\":4}]. Type may be any resolvable Ghidra data type or existing struct name. Set replace_placeholder=true to delete a 1-byte demangler/placeholder type with the same name before creating. To change size of an existing struct in place, use resize_struct; for atomic delete+recreate, use recreate_struct (see docs/STRUCT_RESIZE_WORKFLOW.md).",
        "Create a structure data type. Body fields must be a JSON array of objects; each object needs name and type, with optional offset. Example fields: [{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},{\"name\":\"pNext\",\"type\":\"void *\",\"offset\":4}]. Type may be any resolvable Ghidra data type or existing struct name. Set replace_placeholder=true to delete a 1-byte demangler/placeholder type with the same name before creating. To change size of an existing struct in place, use resize_struct; for atomic delete+recreate, use recreate_struct"
    ),
    (
        "Program name; omit for active; specify when multiple programs are open",
        ""
    ),
    (
        "Target program name",
        ""
    ),
    (
        "List all physical address spaces in the program. On programs with multiple address spaces (e.g., embedded targets), use the returned space names to prefix addresses (e.g., mem:1000, code:ff00) for unambiguous resolution. Also check addressable_unit_size: a value > 1 means the space is word-addressed (e.g., AVR code space uses 2-byte words). MCP tools and Ghidra both use word addresses natively for such spaces — code:001478 is word 0x1478, not byte 0x1478. Do NOT multiply or divide addresses seen in Ghidra output; use them as-is. Overlay spaces are also listed, each marked is_overlay=true with its overlayed_space (base). Address an overlay location as <overlay>::<hex> (e.g., cli.Initial::00010000) — overlay names are case-sensitive.",
        "Use the returned space names to prefix addresses (e.g mem:1000, code:ff00)"
        "for unambiguous resolution. The returned result must be used AS-IS."
        "Used for program with multiple address spaces"
    ),
    (
        "Bulk merge: copy ALL RE documentation from one program to another at matching addresses, in a single server-side transaction. Categories: function names + signatures + plate comments + locals + calling convention + no-return + tags; standalone data types; data definitions (typed globals); plate comments at any address; comments at all 4 types (EOL/PRE/POST/REPEATABLE) on instructions AND data; labels & globals (with namespace preservation); external locations (ordinal renames); bookmarks; equates. Designed for the orphan-rescue workflow: source is typically '<name>_recovered', target is the original '<name>.dll'. Idempotent — re-running on an already-merged target only fills gaps. Set dry_run=true to count without writing.",
        "copy all RE documentation from one program to another, at matching addresses "
        "Designed for the orphan-rescue workflow: source is typically '<name>_recovered', target is the original '<name>.dll' "
        "the action is Idempotent"
    ),
)


def _compact_description(description: str) -> str:
    for verbose, concise in _DESCRIPTION_REPLACEMENTS:
        description = description.replace(verbose, concise)
    return description


def _compact_input_schema(schema: dict) -> dict:
    """Copy a JSON Schema for publication, dropping titles and repeated prose.

    Walk schema keywords only: a property named ``title`` is an argument, and
    default/enum/example objects are data, not schemas. Defaults, constraints,
    required fields and nullable unions are kept as generated by FastMCP.
    """
    compact = {key: value for key, value in schema.items() if key != "title"}
    if isinstance(compact.get("description"), str):
        compact["description"] = _compact_description(compact["description"])
    for key in ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas"):
        if isinstance(compact.get(key), dict):
            compact[key] = {
                name: _compact_input_schema(value) if isinstance(value, dict) else value
                for name, value in compact[key].items()
            }
    for key in (
        "items", "additionalItems", "additionalProperties", "unevaluatedProperties",
        "unevaluatedItems", "contains", "propertyNames", "not", "if", "then", "else", "contentSchema",
    ):
        if isinstance(compact.get(key), dict):
            compact[key] = _compact_input_schema(compact[key])
    for key in ("allOf", "anyOf", "oneOf", "prefixItems", "items"):
        if isinstance(compact.get(key), list):
            compact[key] = [
                _compact_input_schema(value) if isinstance(value, dict) else value
                for value in compact[key]
            ]
    return compact


# JSON type → Python type mapping
_TYPE_MAP = {
    "string": str,
    "json": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
    "any": str,
    "address": str,
}


def _normalize_tool_def_names(schema: list[dict]) -> list[dict]:
    """Normalize and de-duplicate MCP-visible names while keeping HTTP endpoints intact."""
    normalized_schema: list[dict] = []
    used_names = set(STATIC_TOOL_NAMES)

    for tool_def in schema:
        raw_name = (
            tool_def.get("original_name")
            or tool_def.get("name")
            or tool_def["endpoint"].lstrip("/")
        )
        sanitized_name = sanitize_tool_name(raw_name)

        # Collision detection uses the ACTIVE static set: when the WinDbg debugger
        # proxies are off (the default), their names are free, so Ghidra's own
        # TraceRmi /debugger/* endpoints (System B) keep clean names instead of _2.
        #
        # Preserve the existing behavior for valid dynamic names that exactly
        # overlap a static bridge tool: _register_tool_def will skip them.
        if sanitized_name in _ALL_STATIC_TOOL_NAMES and sanitized_name == raw_name:
            name = sanitized_name
        else:
            name = _allocate_tool_name(sanitized_name, used_names)

        normalized = dict(tool_def)
        normalized["name"] = name
        normalized["original_name"] = raw_name
        normalized["sanitized_name"] = sanitized_name
        normalized["name_collided"] = name != sanitized_name
        normalized_schema.append(normalized)

    return normalized_schema


def _parse_schema(raw: dict) -> list[dict]:
    """Convert upstream AnnotationScanner schema to internal tool defs.

    Upstream format: {"tools": [{"path", "method", "description", "category", "params": [...]}]}
    Internal format: [{"name", "endpoint", "http_method", "description", "category", "input_schema"}]
    """
    tool_defs = []
    for tool in raw.get("tools", []):
        path = tool["path"]
        raw_name = tool.get("name") or path.lstrip("/")
        params = tool.get("params", [])

        properties = {}
        required = []
        for p in params:
            pdef: dict = {"type": p.get("type", "string")}
            if p.get("description"):
                pdef["description"] = p["description"]
            if "default" in p and p["default"] is not None:
                pdef["default"] = p["default"]
            if p.get("source"):
                pdef["source"] = p["source"]
            if p.get("param_type"):
                pdef["param_type"] = p["param_type"]
            # Alternative spellings the server accepts for this parameter
            # (@Param(aliases = {...})). AnnotationScanner resolves the canonical
            # name first and then each alias, so both reach the same argument.
            # Carried through so registry.handler can fold an alias onto its
            # canonical name instead of the bridge dropping it on the floor.
            if p.get("aliases"):
                pdef["aliases"] = [str(a) for a in p["aliases"]]
            # Carried through so the dispatch handler knows not to drop an
            # empty-string argument for this parameter (e.g. clearing a
            # comment). See registry.handler's filtering.
            if p.get("allow_empty"):
                pdef["allow_empty"] = True
            properties[p["name"]] = pdef
            if p.get("required", False):
                required.append(p["name"])

        tool_def = {
                "name": raw_name,
                "original_name": raw_name,
                "endpoint": path,
                "http_method": tool.get("method", "GET"),
                "description": tool.get("description", ""),
                "category": tool.get("category", "unknown"),
                "category_description": tool.get("category_description", ""),
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
        }
        # Present only for tools the server has classified (@McpTool's
        # `access`). Absent means "unclassified": the bridge then emits no MCP
        # annotations at all rather than guessing, because a wrong
        # readOnlyHint=true lets a mutating tool run unattended.
        if "read_only" in tool:
            tool_def["read_only"] = bool(tool["read_only"])
            tool_def["destructive"] = bool(tool.get("destructive", False))
        tool_defs.append(tool_def)

    return _normalize_tool_def_names(tool_defs)
