"""Schema parsing — converts the upstream /mcp/schema to internal tool defs."""

from .config import STATIC_TOOL_NAMES, _ALL_STATIC_TOOL_NAMES
from .schema_descriptions import DESCRIPTION_REPLACEMENTS
from .validation import sanitize_tool_name, _allocate_tool_name

# Optional tools hidden from the everyday reverse-engineering tool surface.
# Use exact bridge names, before client-added prefixes (e.g. ghidra_).
# Remove a name and restart the bridge to restore it; HTTP endpoints stay intact.
HIDE_OPTIONAL_TOOL_NAMES = {
    # Local computation and basic naming heuristics.
    "convert_number",
    "suggest_field_names",
    "detect_array_bounds",
    # Overlapping decompilation and program metadata reads.
    "force_decompile",
    "get_function_count",
    # Overlapping discovery/preflight helpers and GUI window inventory.
    "find_next_undefined_function",
    "can_rename_at_address",
    "tool_running_tools",
    # Overlapping function bundles and documentation-specific scoring.
    "analyze_function_complete",
    "analyze_for_documentation",
    "analyze_function_completeness",
    "analyze_global_completeness",
    # API-name-based malware triage.
    "analyze_api_call_chains",
    "detect_malware_behaviors",
    # Ghidra Server administration and version control.
    "checkin_program",
    "server_admin_set_permissions",
    "server_admin_terminate_all_checkouts",
    "server_admin_terminate_checkout",
    "server_admin_users",
    "server_authenticate",
    "server_checkouts",
    "server_connect",
    "server_disconnect",
    "server_repositories",
    "server_repository_create",
    "server_repository_file",
    "server_repository_files",
    "server_status",
    "server_version_control_add",
    "server_version_control_checkout",
    "server_version_control_undo_checkout",
    "server_version_history",
    # Project housekeeping; retain project/program discovery, import and export.
    "archive_project",
    "create_folder",
    "delete_file",
    "delete_project",
    "move_file",
    "move_folder",
    "restore_project",
    # Custom program property-map storage.
    "create_property_map",
    "delete_property_map",
    "get_property",
    "list_properties",
    "remove_property",
    "set_property",
    # Useful, but unused
    "debugger_attach",
    "debugger_continue",
    "debugger_detach",
    "debugger_dynamic_to_static",
    "debugger_interrupt",
    "debugger_launch",
    "debugger_launch_offers",
    "debugger_list_breakpoints",
    "debugger_modules",
    "debugger_read_args",
    "debugger_read_memory",
    "debugger_registers",
    "debugger_remove_breakpoint",
    "debugger_resolve_ordinal",
    "debugger_resume",
    "debugger_set_breakpoint",
    "debugger_stack_trace",
    "debugger_static_to_dynamic",
    "debugger_status",
    "debugger_step",
    "debugger_step_into",
    "debugger_step_over",
    "debugger_trace_function",
    "debugger_trace_list",
    "debugger_trace_log",
    "debugger_trace_stop",
    "debugger_traces",
    "debugger_watch_log",
    "debugger_watch_memory",
    "debugger_watch_stop",
    "exit_ghidra",
    "emulate_function",
    "emulate_hash_batch",
    "export_program",
    "extract_iocs_with_context",
    "find_anti_analysis_techniques",
    "import_program",
    "close_program",
    "find_similar_functions",
    "find_undocumented_by_string",
    "open_program",
    "analyze_call_graph",
    "add_function_tag",
    "add_memory_reference",
    "add_struct_field",
    "analysis_status",
    "analyze_control_flow",
    "analyze_struct_field_usage",
    "apply_data_classification",
    "apply_data_type",
    "apply_documentation",
    "apply_function_documentation",
    "archive_ingest_function",
    "archive_ingest_program",
    "audit_global",
    "audit_globals_in_function",
    "batch_add_function_tags",
    "batch_analyze_completeness",
    "batch_create_labels",
    "batch_delete_labels",
    "batch_remove_function_tags",
    "batch_string_anchor_report",
    "bulk_fuzzy_match",
    "clear_function_comments",
    "clear_instruction_flow_override",
    "clone_data_type",
    "compare_programs_documentation",
    "configure_analyzer",
    "create_data_type_category",
    "create_function",
    "create_function_signature",
    "create_function_tag",
    "create_label",
    "create_memory_block",
    "create_typedef",
    "delete_bookmark",
    "delete_data_type",
    "delete_function",
    "delete_function_tag",
    "delete_label",
    "embed_struct_field",
    "find_code_gaps",
    "find_similar_functions_fuzzy",
    "get_address_spaces",
    "get_bulk_function_hashes",
    "get_bulk_xrefs",
    "get_entry_points",
    "get_enum_values",
    "get_field_access_context",
    "get_full_call_graph",
    "get_function_hash",
    "get_function_jump_targets",
    "get_function_labels",
    "get_function_pcode",
    "get_function_tags",
    "get_language_metadata",
    "get_plate_comment",
    "get_program_options",
    "get_project_info",
    "get_type_size",
    "get_ui_cursor",
    "import_data_types",
    "import_file",
    "list_analyzers",
    "list_bookmarks",
    "list_calling_conventions",
    "list_class_members",
    "list_classes",
    "list_data_types",
    "list_function_tags",
    "list_functions",
    "list_functions_enhanced",
    "list_methods",
    "list_option_groups",
    "list_property_maps",
    "list_shadowed_globals",
    "merge_program_documentation",
    "modify_struct_field",
    "modify_struct_field_type",
    "move_data_type_to_category",
    "open_project",
    "reanalyze",
    "remove_function_tag",
    "remove_program_option",
    "remove_reference",
    "remove_struct_field",
    "rename_data_type",
    "rename_external_location",
    "rename_function",
    "rename_global_variable",
    "rename_label",
    "rename_or_label",
    "resolve_duplicate_type",
    "run_analysis",
    "save_all_programs",
    "search_functions_by_tag",
    "search_functions_enhanced",
    "set_bookmark",
    "set_decompiler_comment",
    "set_decompiler_variable_type",
    "set_function_no_return",
    "set_function_tag_comment",
    "set_function_this_type",
    "set_global",
    "set_image_base",
    "set_local_variable_type",
    "set_memory_block",
    "set_parameter_type",
    "set_program_option",
    "set_variable_storage",
    "set_variables",
    "tool_goto_address",
    "validate_function_prototype",
}

# Additional exclusions, combined with the optional-tool list above.
# Also applies to static bridge tools. Edit either set, then restart the bridge.
DISABLED_TOOL_NAMES = {
    "clear_flow_and_repair",  # schema bloated + not frequently used
    # Unimplemented analysis endpoints.
    "find_dead_code",
    "detect_crypto_constants",
    # Schema/server diagnostics and specialized GUI automation.
    "mcp_schema",
    "mcp_health",
    "prompt_policy",
    # All tools are loaded up front; lazy-load management is unnecessary.
    "list_tool_groups",
    "load_tool_group",
    "unload_tool_group",
    "check_tools",
    "search_tools",
} | HIDE_OPTIONAL_TOOL_NAMES

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
        "Naming enforcement: enforce/reject, warn/write with warnings, off/skip. Omit for project/global setting."
    ),
    (
        "Optional per-call override for naming enforcement: 'enforce' / 'warn' / 'off'. "
        "Omit to use the project/global setting.",
        "Naming enforcement: enforce/warn/off. Omit for project/global setting.",
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
        "Number of entries to skip before this page starts; 0 begins at the first entry. "
        "Page by adding `limit` each call until offset reaches the `total` the response reports.",
        "Entries to skip (0 = first). Advance by `limit` until offset reaches response `total`.",
    ),
    (
        "Maximum entries returned in this page (default 100). Pass 0 or a negative value "
        "for no limit; `total` in the response always reports the full unpaged count.",
        "Page size (default 100); <=0 = unlimited. Response `total` is the unpaged count.",
    ),
    (
        "Maximum entries returned in this page (default 500). Pass 0 or a negative value "
        "for no limit; `total` in the response always reports the full unpaged count.",
        "Page size (default 500); <=0 = unlimited. Response `total` is the unpaged count.",
    ),
    (
        "Page size. 0 means no limit, which on a large binary is a megabytes-long response "
        "— the old list_functions had no pagination at all and returned 1.7MB on a stripped `ls`.",
        "Page size; 0 = unlimited (can return megabytes on large binaries).",
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

_DESCRIPTION_REPLACEMENTS += DESCRIPTION_REPLACEMENTS


def _compact_description(description: str) -> str:
    for verbose, concise in _DESCRIPTION_REPLACEMENTS:
        description = description.replace(verbose, concise)
    return description


def _parameter_aliases(properties: dict) -> dict[str, str]:
    """Resolve declared aliases without shadowing canonical or earlier names."""
    aliases = {}
    for canonical, param in properties.items():
        for alias in param.get("aliases") or ():
            if alias not in properties and alias not in aliases:
                aliases[alias] = canonical
    return aliases


def _canonical_input_schema(schema: dict, definition: dict) -> dict:
    """Hide confirmed aliases in an advertised copy, restoring required names.

    Keep canonical parameter schemas intact, including their nullable unions
    and defaults. Internal FastMCP models still accept the legacy spellings.
    """
    aliases = _parameter_aliases(definition.get("properties", {}))
    properties = schema.get("properties", {})
    if not aliases:
        return schema
    published = dict(schema)
    published["properties"] = {name: value for name, value in properties.items() if name not in aliases}
    required = list(schema.get("required", []))
    for name in definition.get("required", []):
        if name in aliases.values() and name in properties and name not in required:
            required.append(name)
    if required:
        published["required"] = required
    return published


def _compact_input_schema(schema: dict) -> dict:
    """Copy a JSON Schema, dropping titles, empty descriptions and repeated prose.

    Walk schema keywords only: a property named ``title`` is an argument, and
    default/enum/example objects are data, not schemas. Defaults, constraints,
    required fields and nullable unions are kept as generated by FastMCP.
    """
    compact = {key: value for key, value in schema.items() if key != "title"}
    if isinstance(compact.get("description"), str):
        description = _compact_description(compact["description"])
        if description.strip():
            compact["description"] = description
        else:
            compact.pop("description")
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
