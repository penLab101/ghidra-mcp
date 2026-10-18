"""Exact rewrites of verbose tool/parameter descriptions for MCP publication.

Preserve call constraints and warnings; unknown wording passes through unchanged.
"""

from textwrap import dedent


DESCRIPTION_REPLACEMENTS = (
    (
        "Everything about one or many functions in a single call. Pass functions= as a comma-separated list of "
        "names or addresses for bulk mode (up to 20); omit it and pass function=/name=/address= for one. Pass "
        "fields= as a comma-separated subset to skip work you do not need — omitted or empty returns everything. "
        "When the requested fields need no decompiled text (e.g. "
        "fields=callers,callees,signature,labels,entry_point), the target function is NOT decompiled (238 ms cold"
        " / 5–10 ms warm per function); only decompiled_code (and call_context when enabled) pays that cost. "
        "Decompiled text renders EOL comments (// style), so comments written with set_comment are visible in the"
        " code. Replaces get_function_by_address, get_function_variables, get_function_xrefs, decompile_function,"
        " and the former get_function_callers/callees/labels/signature tools. Completeness scoring is NOT "
        "included — call analyze_function_completeness for that.",
        "Read one function (function/name/address) or up to 20 (functions, comma-separated). fields selects "
        "output; empty = all. Decompiles only for decompiled_code, refs or enabled call_context. Code includes "
        "EOL comments. For completeness scores use analyze_function_completeness.",
    ),
    (
        "Everything about one or many functions in a single call. Pass functions= as a comma-separated list of "
        "names or addresses for bulk mode (up to 20); omit it and pass function=/name=/address= for one. Pass "
        "fields= as a comma-separated subset to skip work you do not need — omitted or empty returns everything. "
        "When the requested fields need no decompiled text (e.g. "
        "fields=callers,callees,signature,labels,entry_point), the target function is NOT decompiled (238 ms cold"
        " / 5–10 ms warm per function); only decompiled_code (and call_context when enabled) pays that cost. "
        "Decompiled text renders EOL comments (// style), so comments written with set_comment are visible in the"
        " code. Replaces get_function_by_address, get_function_variables, get_function_xrefs, decompile_function,"
        " get_function_bundle, and the former get_function_callers/callees/labels/signature tools. Completeness "
        "scoring is NOT included — call analyze_function_completeness for that.",
        "Read one function (function/name/address) or up to 20 (functions, comma-separated). fields selects "
        "output; empty = all. Decompiles only for decompiled_code, refs or enabled call_context. Code includes "
        "EOL comments. For completeness scores use analyze_function_completeness.",
    ),
    (
        "\n    Import a binary file from disk into the current Ghidra project.\n\n    Imports the file, opens it in "
        "the CodeBrowser, and optionally starts auto-analysis.\n    When analysis is enabled, sends a log "
        "notification when analysis completes.\n\n    For raw firmware binaries, specify language (e.g. "
        "\"ARM:LE:32:Cortex\") and\n    optionally compiler_spec (e.g. \"default\"). Without language, Ghidra "
        "auto-detects\n    the format (works for ELF, PE, Mach-O, etc.).\n\n    Args:\n        file_path: Absolute "
        "path to the binary file on disk\n        project_folder: Destination folder in the Ghidra project "
        "(default: \"/\")\n        language: Language ID for raw binaries (e.g. \"ARM:LE:32:Cortex\", "
        "\"x86:LE:64:default\")\n        compiler_spec: Compiler spec ID (e.g. \"default\", \"gcc\"). Uses language "
        "default if omitted.\n        auto_analyze: Start auto-analysis after import (default: true)\n    ",
        "Import a host binary into the project and open it in CodeBrowser. Auto-analysis defaults on; completion "
        "sends a log notification. Raw binaries require language (e.g. ARM:LE:32:Cortex); compiler_spec defaults "
        "to that language. Other formats are auto-detected.",
    ),
    (
        "Import a binary file from disk into the open project and open it. If the destination folder already "
        "holds a file of that name, that file is opened instead (reused_existing: true). For raw firmware "
        "binaries, specify language (e.g. 'ARM:LE:32:Cortex') and optionally compiler_spec (e.g. 'default').",
        "Import/open a host binary; existing destination files are reused (reused_existing=true). Raw firmware "
        "needs language (e.g. ARM:LE:32:Cortex); compiler_spec is optional.",
    ),
    (
        "\n    Switch the MCP bridge to a different Ghidra instance by project name.\n\n    IMPORTANT: Before "
        "calling this function only the static bridge tools are\n    exposed (list_instances, connect_instance, "
        "tool-group management,\n    debugger proxy). After a successful connect the bridge fetches the\n    "
        "instance's /mcp/schema and registers Ghidra analysis tools dynamically.\n    By default all tool groups "
        "are loaded on connect. When started with\n    --lazy, only the default groups are loaded initially and "
        "clients may need\n    to call load_tool_group() for additional categories. Clients that cache\n    the "
        "initial tools/list and don't honor tools/list_changed must re-list\n    tools after this call.\n\n    Use "
        "list_instances() first to see available instances.\n\n    Args:\n        project: Project name (or "
        "substring) to connect to\n    ",
        "Connect by project name or substring; discover with list_instances. Fetches the instance schema and "
        "registers analysis tools (all by default; --lazy loads default groups). Clients must refresh tools/list "
        "if they ignore tools/list_changed.",
    ),
    (
        "Score a global variable's documentation completeness on a budgeted 0-100 scale — the data-address analog"
        " of analyze_function_completeness. Six axes: meaningful name, explanatory plate comment, real type, "
        "formatted bytes (core, drive effective_score + DOC_DRAFT) plus enum/equate and struct membership "
        "(advanced, forgiven in effective_score). A global with no real type (no defined data, or an undefined* "
        "type) is hard-capped at 79 and can never band COMPLETE_80 or above, no matter how good its name and "
        "comment are — apply a type with set_global first. Returns raw score, effective_score, COMPLETE_<band>, "
        "per-axis breakdown, and which axes are still missing.",
        "Score global documentation 0-100: name, plate comment, type, formatted bytes, enum/equate, struct "
        "membership. effective_score forgives the last two axes; missing/undefined types cap it at 79 (apply "
        "set_global). Returns raw/effective scores, COMPLETE_<band> and missing axes.",
    ),
    (
        "Set a parameter's or local's storage location to a register, register pair, or stack slot. Accepts "
        "'EAX', 'EAX:4', 'R0:4,R2:4' or 'Stack[-0x10]:4'; size defaults to the variable's data-type length. Use "
        "this when the argument layout cannot be expressed by any calling convention. Setting a PARAMETER's "
        "storage switches the whole function to custom variable storage (reported as custom_storage_enabled). The"
        " storage is read back after the write and returned in 'storage'. On programs with multiple address "
        "spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous "
        "resolution.",
        "Set parameter/local storage: EAX, EAX:4, R0:4,R2:4 or Stack[-0x10]:4; omitted size uses type length. "
        "Parameter changes enable custom storage for the entire function. Returns storage read back after "
        "writing. Multi-space addresses: mem:1000.",
    ),
    (
        "List one kind of program inventory with pagination. Replaces list_classes, list_methods, "
        "list_namespaces, list_imports, list_exports, list_segments, list_data_items and list_external_locations "
        "— one envelope ({kind, items, count, total, limit, offset}), item shape varies by kind: "
        "classes|methods|namespaces → string names; imports|exports → {address, name}; segments → {name, start, "
        "end, size, readable, writable, executable, initialized}; data_items → {address, block, label, size, "
        "type}; external_locations → {name, library, address, original_imported_name?}. Unknown kind is an error "
        "listing the valid values.",
        "Paginated inventory; envelope: {kind,items,count,total,limit,offset}. classes/methods/namespaces: names;"
        " imports/exports: {address,name}; segments: name/start/end/size/permissions/initialized; data_items: "
        "address/block/label/size/type; external_locations: name/library/address/original_imported_name?. Invalid"
        " kind lists valid values.",
    ),
    (
        "Type the implicit 'this' of a __thiscall/__fastcall member function by associating the function with its"
        " class. Ghidra's auto-'this' (ECX on x86) is an immutable auto-parameter; with auto-storage it derives "
        "its type from the function's parent Class namespace, matched by name to a same-named structure. This "
        "tool finds/creates a class namespace for the struct and moves the function into it (no custom storage). "
        "Pass 'MyClass *' or 'MyClass'; the structure MyClass must already exist (create_struct). On programs "
        "with multiple address spaces, prefix function_address with the space name (mem:1000).",
        "Type implicit this on __thiscall/__fastcall functions by moving them into the class namespace of an "
        "EXISTING struct (create_struct first). Accepts MyClass or MyClass *. Uses auto-storage, not custom "
        "storage. Multi-space function addresses: mem:1000.",
    ),
    (
        "Set the decompiler/database type of the implicit 'this' pointer (ECX on x86 __thiscall/__fastcall). Use "
        "after set_function_prototype when decompile still shows void* this or a wrong class. Accepts 'MyClass *'"
        " or 'MyClass'. On programs with multiple address spaces, prefix function_address with the space name "
        "(mem:1000).",
        "Type implicit this on __thiscall/__fastcall functions by moving them into the class namespace of an "
        "EXISTING struct (create_struct first). Accepts MyClass or MyClass *. Uses auto-storage, not custom "
        "storage. Multi-space function addresses: mem:1000.",
    ),
    (
        "Archive the currently open project to a Ghidra-native .gar file. The result can be restored into any "
        "Ghidra GUI via File → Restore Project, or back into a headless instance via /restore_project. Captures "
        "the entire project (all programs, folders, settings, version-control metadata) — unlike /export_program "
        "which ships a single program as .gzf. Output is written to `output_dir/output_name` (defaults: "
        "/data/exports and `<project>.gar`). Refuses to overwrite an existing file, and refuses while an open "
        "program has unsaved changes, since the archive would not contain them: save first.",
        "Archive the entire project, including settings and version-control metadata, to .gar; restore via GUI or"
        " restore_project. Defaults to /data/exports/<project>.gar. Refuses overwrite or unsaved open programs; "
        "save first. For one program use export_program (.gzf).",
    ),
    (
        "Get assembly listing of function. On programs with multiple address spaces (e.g., embedded targets), "
        "prefix addresses with the space name (mem:1000) to avoid ambiguous resolution. When Ghidra's stored "
        "function body is degenerate (body_end == body_start, which would truncate the listing to a single "
        "instruction), the listing is instead bounded by the next function or the containing memory block and the"
        " response adds body_degenerate=true, bounded_by (next_function | memory_block | function_body) and a "
        "warning; do not trust this function's stored extent in that case.",
        "Read function assembly (multi-space addresses: mem:1000). If body_end == body_start, bounds by next "
        "function or memory block and reports body_degenerate=true, bounded_by and a warning; stored function "
        "extent is unreliable.",
    ),
    (
        "List global DATA symbols. By default returns every global in the program (named + unnamed-but-xrefed "
        "undefined addresses). `filter` and `type_filter` (each: all/defined/undefined) compose orthogonally to "
        "scope the result — e.g., `filter=named, type_filter=undefined` returns the cleanup backlog (placeholders"
        " awaiting real types). `min_xrefs` (default 1) suppresses zero-xref noise when including undefined "
        "items. Code labels (branch targets, error handlers) are still excluded — they're not data globals. Each "
        "line ends with `xrefs=N` for prioritization.",
        "List DATA globals, excluding code labels; includes named and unnamed xrefed addresses by default. filter"
        " and type_filter independently select naming/type status. min_xrefs defaults to 1 for undefined items. "
        "Each line includes xrefs=N.",
    ),
    (
        "What the analyst is looking at right now: cursor address, the function under it, the listing selection, "
        "and the focused program — one call instead of four. type=address|function|selection|program|all (default"
        " all). Takes NO program parameter: the focused program is an answer this reports, not an input. Headless"
        " has no analyst and no cursor, so every facet reports null with a reason there — use the program "
        "parameter on a data endpoint instead. Replaces get_current_address, get_current_function, "
        "get_current_selection and get_current_program_info.",
        "Read GUI cursor address, function, selection and focused program. "
        "type=address|function|selection|program|all (default). No program input. Headless returns null facets "
        "with reasons; use a data endpoint with program instead.",
    ),
    (
        "Create a structure data type. Body fields must be a JSON array of objects; each object needs name and "
        "type, with optional offset. Example fields: "
        "[{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},{\"name\":\"pNext\",\"type\":\"void *\",\"offset\":4}]. Type may be any "
        "resolvable Ghidra data type or existing struct name. Set replace_placeholder=true to delete a 1-byte "
        "demangler/placeholder type with the same name before creating. To change size of an existing struct in "
        "place, use resize_struct; for atomic delete+recreate, use recreate_struct",
        "Create struct from fields=[{name,type,offset?}]; types must resolve. replace_placeholder deletes a "
        "same-name 1-byte placeholder first. Use resize_struct to resize in place or recreate_struct for atomic "
        "replacement.",
    ),
    (
        "Create structure. Body fields must be a JSON array of objects with name and type, plus optional decimal "
        "offset. Example fields: [{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},{\"name\":\"pNext\",\"type\":\"void "
        "*\",\"offset\":4}]. Type may be any resolvable Ghidra data type or existing struct name.",
        "Create struct from fields=[{name,type,offset?}]; types must resolve. replace_placeholder deletes a "
        "same-name 1-byte placeholder first. Use resize_struct to resize in place or recreate_struct for atomic "
        "replacement.",
    ),
    (
        "Apply documentation to ONE function (fields at the top level) OR MANY (entries=[{address, ...}, ...]). "
        "Per function, every step is optional and independent and the response reports each one: rename, "
        "signature, variable types and renames, comments, labels, then a completeness score. It accepts what "
        "get_function_documentation exports (with target_address), so documentation copied between versions "
        "applies as it is. The signature is applied before the comments on purpose, because setting a prototype "
        "wipes the plate comment.",
        "Document one function with top-level fields or many with entries=[{address,...}]. Optional independent "
        "steps report results: rename, signature, variable types/renames, comments, labels, completeness. Accepts"
        " get_function_documentation output with target_address. Signature precedes comments because prototypes "
        "erase plate comments.",
    ),
    (
        "Find functions: every filter is optional, so with none it lists the whole program a page at a time. "
        "Filter by name (substring or regex=true), xref count, calling convention, whether the name is "
        "user-given, thunk or external, or by tag (tag=a,b keeps functions carrying ANY of them); each result "
        "lists its tags; sort by address, name or xref_count. Replaces list_functions, list_functions_enhanced, "
        "search_functions and search_functions_enhanced, which returned four different shapes for the same "
        "question.",
        "Find/list functions with pagination. Optional filters: name substring/regex, xref count, calling "
        "convention, user-named, thunk, external, tags (comma-separated; ANY match). Results include tags; sort "
        "by address/name/xref_count.",
    ),
    (
        "List named global DATA symbols that have NO type of their own because a larger data unit starting at an "
        "earlier address covers them. These are invisible to /list_globals — it resolves the CONTAINING unit, so "
        "it reports the covering neighbour's type at the shadowed address and the global looks perfectly typed. "
        "Each record carries the container that swallowed it. Use this to find documentation that a neighbouring "
        "type application destroyed, or a symbol sitting inside an array where it does not belong.",
        "Find named DATA globals covered by an earlier, larger data unit, with container details. list_globals "
        "reports the containing type and misses these globals lacking their own type.",
    ),
    (
        "List named global DATA symbols that have NO type of their own because a larger data unit starting at an "
        "earlier address covers them. These are invisible to /list_globals - it resolves the CONTAINING unit, so "
        "it reports the covering neighbour's type at the shadowed address and the global looks perfectly typed. "
        "Each record carries the container that swallowed it. Use this to find documentation that a neighbouring "
        "type application destroyed, or a symbol sitting inside an array where it does not belong.",
        "Find named DATA globals covered by an earlier, larger data unit, with container details. list_globals "
        "reports the containing type and misses these globals lacking their own type.",
    ),
    (
        "Get listing comments (plate/pre/eol/post/repeatable) at ANY address, including data addresses (works on "
        "functions and data globals alike), for ONE address (address=) or MANY in one call (addresses=a,b,c). All"
        " five kinds are always present in each result: null means the kind was never set, \"\" means it was "
        "explicitly cleared. Each result also has a convenience `comment` (first non-empty) and `has_comment` "
        "flag. Bulk mode wraps the results with requested / returned / with_comments counts.",
        "Read all five comment kinds at code/data addresses: address or addresses=a,b,c. null = never set; empty "
        "string = explicitly cleared. Results include first nonempty comment and has_comment; bulk adds "
        "requested/returned/with_comments counts.",
    ),
    (
        "Export a program to a GZF (Ghidra packed-database) file on disk. The resulting .gzf can be imported into"
        " any Ghidra GUI (File → Import) or back into a project via /import_program. Resolution order: (1) the "
        "in-memory program with that name (captures live analyst edits); (2) a DomainFile in the open project "
        "(on-disk state). Output is written to `output_dir/output_name` (defaults: /data/exports and "
        "`<program>.gzf`). Refuses to overwrite an existing file.",
        "Export .gzf, resolving an open in-memory program first (live edits), then project DomainFile (disk). "
        "Defaults to /data/exports/<program>.gzf; refuses overwrite. Import via GUI or import_program.",
    ),
    (
        "Export an open or project-resident program to a Ghidra Zip File (.gzf). Looks up the program in the "
        "open-programs map first (so it works on file-loaded programs without a project), then falls back to the "
        "open project's DomainFile.",
        "Export .gzf, resolving an open in-memory program first (live edits), then project DomainFile (disk). "
        "Defaults to /data/exports/<program>.gzf; refuses overwrite. Import via GUI or import_program.",
    ),
    (
        "Remove memory cross-reference(s) from one address to another (the inverse of add_memory_reference). "
        "Removes every reference from_address -> to_address regardless of operand by default; pass operand_index "
        ">= 0 to remove only the reference on that operand. Removes both user-defined and analyzer-inferred "
        "references — the response reports each removed reference's source_type. On multi-space programs, prefix "
        "addresses with the space name (mem:1000).",
        "Remove all from_address -> to_address memory refs, or only operand_index >=0. Removes user/analyzer refs"
        " and reports each source_type. Multi-space addresses: mem:1000.",
    ),
    (
        "Remove memory cross-reference(s) from one address to another — the inverse of add_memory_reference. "
        "Removes every reference from_address -> to_address regardless of operand by default; pass operand_index "
        ">= 0 to remove only the reference on that operand. Removes both user-defined and analyzer-inferred "
        "references and reports each removed reference's source_type. Accepts space-prefixed addresses "
        "(mem:1000).",
        "Remove all from_address -> to_address memory refs, or only operand_index >=0. Removes user/analyzer refs"
        " and reports each source_type. Multi-space addresses: mem:1000.",
    ),
    (
        "Close an open program by project path or name. Never prompts interactively: unsaved changes are saved "
        "first by default (save=true) or silently discarded (save=false) before closing, so this cannot block the"
        " caller on a GUI confirmation dialog the way Ghidra's own close normally would. save=true is refused "
        "when the edits cannot be saved (a versioned file that is not checked out), rather than closing and "
        "losing them.",
        "Close by project path/name without prompting. save=true (default) saves edits first and refuses if "
        "unsavable (e.g. versioned file not checked out); save=false discards edits.",
    ),
    (
        "Close an open program by project path or name. Never prompts interactively: unsaved changes are saved "
        "first by default (save=true) or silently discarded (save=false) before closing, so this cannot block the"
        " caller on a GUI confirmation dialog the way Ghidra's own close normally would.",
        "Close by project path/name without prompting. save=true (default) saves edits first and refuses if "
        "unsavable (e.g. versioned file not checked out); save=false discards edits.",
    ),
    (
        "Disassemble a range of bytes. On programs with multiple address spaces (e.g., embedded targets), prefix "
        "addresses with the space name (mem:1000) to avoid ambiguous resolution. Returns the disassembled "
        "instruction text (mnemonic + operands + bytes) when `include_instructions` is true (default), so callers"
        " working on custom processor definitions (#205) can read back what Ghidra produced without a follow-up "
        "call.",
        "Disassemble a byte range (multi-space addresses: mem:1000). include_instructions=true (default) returns "
        "addresses, mnemonics, operands and raw bytes.",
    ),
    (
        "Trace how a value propagates through a function using the decompiler's PCode graph. Direction 'backward'"
        " walks producers (Varnode.getDef); 'forward' walks consumers (Varnode.getDescendants). Terminates at "
        "constants, parameters, call boundaries, or max_steps. Phi (MULTIEQUAL) nodes are summarized rather than "
        "recursed. On programs with multiple address spaces, prefix addresses with the space name (mem:1000).",
        "Trace PCode values backward to producers or forward to consumers. Stops at constants, parameters, calls "
        "or max_steps; summarizes phi/MULTIEQUAL nodes. Multi-space addresses: mem:1000.",
    ),
    (
        "Check a program in to the shared Ghidra Server as a new version. Saves pending edits and closes the "
        "program first (a file checked in while open must stay checked out). Requires a shared project and the "
        "file checked out. Returns version_before/version/version_bumped. dry_run=true checks everything and "
        "reports what would happen (programs it would save, whether it would close one) without doing any of it.",
        "Check in a new shared-server version; requires shared project and checkout. Saves edits and closes the "
        "program first. Returns version_before/version/version_bumped. dry_run previews without saving, closing "
        "or checking in.",
    ),
    (
        "List data items sorted by xref count (descending). By default returns only defined data items. `filter` "
        "and `type_filter` (each: all/defined/undefined) compose orthogonally to also include unnamed/untyped "
        "addresses — `filter=all,type_filter=all` returns the full data surface (named + DAT_*-style autogen + "
        "raw undefined-with-xrefs). `min_xrefs` (default 1) suppresses zero-xref noise on undefined items.",
        "List data by descending xref count (defined items by default). filter/type_filter independently select "
        "naming/type status: all|defined|undefined; both all include raw undefined addresses with xrefs. "
        "min_xrefs=1 suppresses undefined noise.",
    ),
    (
        "Create a cross-reference between two memory addresses that the auto-analyzer can't infer "
        "(runtime-populated pointer tables, vtables, late-bound function pointers, missed jump/switch tables). "
        "Leaves the underlying bytes untouched and adds proper bidirectional navigation. On programs with "
        "multiple address spaces (e.g. embedded targets), prefix addresses with the space name (mem:1000).",
        "Add a memory xref without changing bytes; supports space-prefixed addresses (mem:1000). ref_type accepts"
        " RefType names; source_type defaults to USER_DEFINED (survives re-analysis).",
    ),
    (
        "Create a user-defined cross-reference between two memory addresses that the auto-analyzer can't infer "
        "(runtime-populated pointer tables, vtables, late-bound function pointers, missed jump/switch tables). "
        "Leaves the underlying bytes untouched while adding proper bidirectional navigation. ref_type accepts any"
        " RefType name (DATA, READ, WRITE, COMPUTED_CALL, UNCONDITIONAL_JUMP, ...); source_type defaults to "
        "USER_DEFINED so refs are distinct from analyzer output and survive re-analysis. Accepts space-prefixed "
        "addresses (mem:1000).",
        "Add a memory xref without changing bytes; supports space-prefixed addresses (mem:1000). ref_type accepts"
        " RefType names; source_type defaults to USER_DEFINED (survives re-analysis).",
    ),
    (
        "Rename a symbol of any kind. kind=auto (default): an address target routes to rename-or-create-label "
        "(handles data/label/any symbol at the address); a name target routes to a global. Force with "
        "kind=data|global|label|external. For kind=label pass old_name (the current label). Replaces rename_data "
        "/ rename_global_variable / rename_label / rename_or_label / rename_external_location.",
        "Rename by target address/name; auto routes addresses to rename/create-label, names to globals. "
        "kind=data|global|label|external forces routing. kind=label needs old_name.",
    ),
    (
        "Set function prototype (return type, parameter types, calling convention) by address. NOTE: the function"
        " name in the prototype string is used only for parsing — it does NOT rename the function. To rename, "
        "call rename_function separately. On programs with multiple address spaces (e.g., embedded targets), "
        "prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.",
        "Set return/parameter types and calling convention by address (multi-space: mem:1000). Prototype name is "
        "discarded; rename_function separately.",
    ),
    (
        "Set function prototype (return type, param types, calling convention). NOTE: the function name in the "
        "prototype string does NOT rename the function — call rename_function separately if needed.",
        "Set return/parameter types and calling convention by address (multi-space: mem:1000). Prototype name is "
        "discarded; rename_function separately.",
    ),
    (
        "Open a program from the open project (by project path, or by filename when unique) and keep it open. On "
        "the GUI it is also shown in a CodeBrowser. Any endpoint's program= opens on demand too; this is for "
        "opening deliberately, analysing on open, or getting diagnostics when a file cannot be opened (the paths "
        "the project does contain, and whether it is bound to a Ghidra Server).",
        "Open by project path or unique filename; GUI also shows CodeBrowser. Supports analysis on open and "
        "failure diagnostics (project paths/server binding). Other endpoints also open on demand via program.",
    ),
    (
        "Audit every global variable referenced from within a function in one call. Walks the function's "
        "instructions, collects unique data references, and returns the per-global audit (same shape as "
        "audit_global) plus a summary of how many are fully documented vs have issues. The killer per-function "
        "pre-flight tool — start every doc pass with this when the function has global xrefs.",
        "Audit unique global data references from a function: per-global audit_global results plus "
        "documented/issues summary.",
    ),
    (
        "Change an existing memory block's permissions or volatility. The one that matters most: firmware loaders"
        " often mark the flash block writable, and the decompiler then treats every literal-pool load as a "
        "variable (iVar2 = DAT_08016e58) instead of folding it into the constant it holds; marking flash "
        "read-only lets peripheral and RAM addresses show as constants or their labels.",
        "Change memory-block permissions/volatility. Making flash read-only lets the decompiler fold literal-pool"
        " loads into constants/labels.",
    ),
    (
        "Import a GZF (Ghidra packed-database) file into the open project. The GZF must already exist on disk at "
        "`gzf_path` (typically staged on a shared volume by the orchestrator). Lands at "
        "`target_folder/target_name` (defaults: `/` and the GZF basename sans `.gzf`). Set `overwrite=true` to "
        "replace an existing program at the destination; otherwise the call fails on collision.",
        "Import an existing host .gzf into the project at target_folder/target_name (defaults: / and filename "
        "without .gzf). overwrite=true deletes any destination first; otherwise collision fails.",
    ),
    (
        "List the member functions of a C++ class. A function counts as a member if it lives in the class's "
        "namespace (e.g. after set_function_this_type re-parents it) OR its implicit 'this' parameter types as "
        "'<class> *'. Each result reports how it matched (namespace / this_type / both). Replaces the manual "
        "'search __thiscall functions then read each signature' workflow.",
        "List C++ members matched by class namespace OR implicit this typed '<class> *'. Reports "
        "namespace/this_type/both per match.",
    ),
    (
        "Search for instructions by mnemonic and/or operand substring. Complement to /search_byte_patterns "
        "(byte-level); this matches after Ghidra has parsed instructions, so you can search for 'mov' + "
        "'[ecx+0xD0]' without knowing the encoding. Case-insensitive substring match on both fields. Returns "
        "{address, function, mnemonic, operands, bytes} per match.",
        "Search parsed instructions: case-insensitive exact mnemonic and operand substring. Returns "
        "address/function/mnemonic/operands/bytes. For raw bytes use search_byte_patterns.",
    ),
    (
        "Set a listing comment of a given kind at ANY address (data or code). type = "
        "plate|pre|eol|post|repeatable (aliases: decompiler=pre, disassembly=eol). Plate writes surface "
        "structural warnings and flush the decompiler cache. Symmetric writer for get_comment; replaces the "
        "former set_plate_comment / set_decompiler_comment / set_disassembly_comment.",
        "Write plate|pre|eol|post|repeatable comments at code/data addresses; aliases: decompiler=pre, "
        "disassembly=eol. Plate writes report structural warnings and flush decompiler cache.",
    ),
    (
        "Set a listing comment of a given kind (plate/pre/eol/post/repeatable) at ANY address, including data "
        "addresses. Symmetric writer for get_comment; sets a PLATE comment on a function or a data global alike.",
        "Write plate|pre|eol|post|repeatable comments at code/data addresses; aliases: decompiler=pre, "
        "disassembly=eol. Plate writes report structural warnings and flush decompiler cache.",
    ),
    (
        "Dump raw P-code for a function (issue #192). Returns low (basic-iter) and high (HighFunction) P-code "
        "with basic blocks and varnodes. Granularity controls output: 'basic' = basic-block iter only (less "
        "memory), 'high' = HighFunction graph (default; includes both BB iter and op-iter). For P-code emulators "
        "/ ML pipelines / alternative decompilers.",
        "Read function P-code with blocks/varnodes. basic = basic-block iteration; high (default) = HighFunction "
        "graph with block/op iteration and SSA info.",
    ),
    (
        "Run an existing Ghidra script file by filename or path. The file must already exist on the Ghidra host; "
        "use run_script_inline for temporary new source. Returns JSON {success, script_name, script_path, "
        "execution_time_seconds, output_captured, console_output?}; Requires GHIDRA_MCP_ALLOW_SCRIPTS=1. "
        "dry_run=true is rejected without execution.",
        "Run an existing host script by filename/path; for new source use run_script_inline. Returns JSON "
        "execution metadata/output; failures include output. Cached build banners may concern other files; check "
        "this script diagnostics/success. Requires GHIDRA_MCP_ALLOW_SCRIPTS=1; rejects dry_run=true.",
    ),
    (
        "Run an existing Ghidra script file by filename or path. The file must already exist on the Ghidra host; "
        "use run_script_inline for new source. Returns JSON {success, script_name, script_path, "
        "execution_time_seconds, output_captured, console_output?}; failures always include output. Cached "
        "'failing in previous build(s)' banners may refer to other files; check success and diagnostics for this "
        "script. Requires GHIDRA_MCP_ALLOW_SCRIPTS=1. dry_run=true is rejected without execution.",
        "Run an existing host script by filename/path; for new source use run_script_inline. Returns JSON "
        "execution metadata/output; failures include output. Cached build banners may concern other files; check "
        "this script diagnostics/success. Requires GHIDRA_MCP_ALLOW_SCRIPTS=1; rejects dry_run=true.",
    ),
    (
        "Compile and run temporary Java GhidraScript code. Source is written under the Ghidra process's "
        "~/ghidra_scripts and deleted after success; failed sources may remain until the next script run. To "
        "reuse, save a separate script file and call run_ghidra_script. Returns JSON {success, console_output, "
        "error?}; compile errors prevent execution. Cached 'failing in previous build(s)' banners may refer to "
        "other files; check success and diagnostics for this script. Requires GHIDRA_MCP_ALLOW_SCRIPTS=1. "
        "dry_run=true is rejected without execution.",
        "Compile/run temporary Java GhidraScript under host ~/ghidra_scripts; deleted on success, failures may "
        "persist until next run. Returns JSON success/console_output/error; compile errors prevent execution. "
        "Cached build banners may concern other files. Requires GHIDRA_MCP_ALLOW_SCRIPTS=1; rejects dry_run=true."
        " For reuse save a file and use run_ghidra_script.",
    ),
    (
        "Comma-separated subset: signature, classification, return_type, entry_point, body_start, body_end, "
        "decompiled_code, plate_comment, comments, labels, tags, parameters, locals, callers, call_context, "
        "callees, xrefs, disassembly, jump_targets, refs (the absolute addresses the function uses: data "
        "references, the values of literal-pool words, and the memory the decompiled code reads and writes, so a "
        "register reached as base + offset is listed by its own address; a pool value is written value<word; "
        "asking for refs decompiles). Omit or leave empty for the full bundle.",
        "Comma-separated: signature, classification, return_type, entry_point, body_start, body_end, "
        "decompiled_code, plate_comment, comments, labels, tags, parameters, locals, callers, call_context, "
        "callees, xrefs, disassembly, jump_targets, refs. Empty = all. refs decompiles; includes "
        "data/literal-pool/effective read-write addresses (base+offset resolved); pool values use value<word.",
    ),
    (
        "Comma-separated subset: signature, classification, return_type, entry_point, body_start, body_end, "
        "decompiled_code, plate_comment, comments, labels, tags, parameters, locals, callers, call_context, "
        "callees, xrefs, disassembly, jump_targets, refs (the absolute addresses the function uses: data "
        "references, the values of literal-pool words, and the memory the decompiled code reads and writes, so a "
        "register reached as base + offset is listed by its own address; asking for refs decompiles). Omit or "
        "leave empty for the full bundle.",
        "Comma-separated: signature, classification, return_type, entry_point, body_start, body_end, "
        "decompiled_code, plate_comment, comments, labels, tags, parameters, locals, callers, call_context, "
        "callees, xrefs, disassembly, jump_targets, refs. Empty = all. refs decompiles; includes "
        "data/literal-pool/effective read-write addresses (base+offset resolved); pool values use value<word.",
    ),
    (
        "New function name in PascalCase, verb first: GetPlayerHealth, not get_player_health and not "
        "PlayerHealth. An UPPERCASE module prefix is allowed and validated separately (MODULE_GetValue). The "
        "quality gate rejects a vague verb carrying fewer than two specifier tokens (ProcessData), a single-token"
        " name (Get), a weak-noun-only name (GetInfo), and a name whose tokens are a strict subset of an existing"
        " function's within the same module prefix. strict_mode downgrades those rejections to warnings.",
        "PascalCase, verb first (GetPlayerHealth); optional UPPERCASE_ module prefix. Rejects vague verbs with <2"
        " specifiers, single tokens, weak nouns (GetInfo), or token subsets of existing names within the same "
        "module. strict_mode can downgrade rejections to warnings.",
    ),
    (
        "The name to apply. A data global should be g_ + Hungarian + descriptor (g_dwPlayerCount); a code label "
        "should be snake_case. Convention misses come back as warnings on an otherwise successful write. "
        "IMPORTANT: at a CODE address with no defined data, this ADDS a label rather than renaming one — the "
        "existing symbol survives and may stay primary, so the listing can still show the old name after a "
        "success. Call delete_label on the old name first when you meant to replace it.",
        "Data: g_ + Hungarian + descriptor (g_dwPlayerCount); code labels: snake_case. Convention misses warn. At"
        " code without data this ADDS a label; old primary may remain. To replace, delete_label on old name "
        "first.",
    ),
    (
        "Memory regions to read back AFTER emulation, as a JSON array: [{\"address\": \"0x408300\", \"length\": 16}, "
        "...]. Needed to observe in-place mutations (e.g. a function that lowercases a string via a pointer "
        "argument) -- the emulator's memory is an ISOLATED overlay and never touches the real program, so a plain"
        " read_memory call after emulation sees only the ORIGINAL unmodified bytes, not the emulated result. This"
        " reads from the emulator's own state instead.",
        "JSON [{\"address\":\"0x408300\",\"length\":16},...] to read emulator memory AFTER execution. Required to "
        "observe in-place mutations: emulator memory is isolated; subsequent read_memory sees original program "
        "bytes.",
    ),
    (
        "JSON array of {address, comment} objects setting PRE comments — the lines the decompiler shows above a "
        "statement. Every entry carries its OWN address (0x<hex> or <space>:<hex>); the top-level `address` is "
        "the function entry and is not used for these. An entry missing either key, or whose address does not "
        "parse, is skipped silently — compare decompiler_comments_set against what you sent. An empty comment "
        "string clears that address's PRE comment.",
        "JSON [{address,comment},...] for PRE/decompiler comments; each uses its OWN address, not top-level "
        "function address. Missing keys/invalid addresses are silently skipped; check decompiler_comments_set. "
        "Empty comment clears PRE.",
    ),
    (
        "JSON array of member objects, same shape as create_struct: required keys name and type; "
        "field_name/fieldName and field_type/fieldType/data_type/dataType are accepted as alternates. Any offset "
        "key is IGNORED — union members all start at 0. A member whose type cannot be resolved is skipped and "
        "reported under fields_skipped instead of failing the call. Names get the project's Hungarian prefix "
        "applied automatically.",
        "JSON [{name,type},...]; aliases: field_name/fieldName, field_type/fieldType/data_type/dataType. Offsets "
        "ignored (all 0). Unresolved types are skipped/reported in fields_skipped. Applies project Hungarian "
        "prefixes.",
    ),
    (
        "Permit this type application to clear NAMED neighbouring globals out of existence. Default false: the "
        "call is rejected with `type_would_evict` plus the list of globals it would destroy. Only set true when "
        "the overlap is genuinely wrong and the other symbol should go — the default exists because a silent "
        "clear deletes another global's documentation and still reports success.",
        "Allow destroying named neighbouring globals/documentation. Default false rejects overlaps with "
        "type_would_evict and affected globals. Enable only for intentional eviction.",
    ),
    (
        "JSON array of parameter objects, e.g. [{\"name\":\"dwId\",\"type\":\"uint\"},{\"name\":\"pUnit\",\"type\":\"void *\"}]. "
        "Only the TYPES are used: parameter names are discarded and the created signature has unnamed arguments. "
        "Parsing is a plain comma/colon split, so a type containing a comma or a colon does not survive it, and a"
        " parameter whose type cannot be resolved is dropped silently.",
        "JSON [{\"name\":\"dwId\",\"type\":\"uint\"},...]. Only types are used; names discarded. Plain comma/colon "
        "splitting cannot handle types containing either. Unresolvable parameter types are silently dropped.",
    ),
    (
        "True (the default) clears whatever code or data occupies the FULL target range first, which is what lets"
        " you retype an address sitting inside a wider existing unit. False leaves existing units alone, and the "
        "write then fails with a conflict if anything overlaps. Clearing is also what arms the guard that refuses"
        " a write which would destroy named neighbours.",
        "true clears code/data over the FULL target range and guards against destroying named neighbours. false "
        "preserves existing units and fails on overlap.",
    ),
    (
        "Function to hash: a name, or an address as 0x<hex> (default space) or <space>:<hex> (e.g., mem:1000, "
        "code:ff00). Some programs — particularly embedded/microcontroller targets — are not "
        "address-space-agnostic; use get_address_spaces to discover spaces before assuming a plain hex address is"
        " unambiguous. Omit to hash many functions (offset, limit, filter).",
        "Function name or 0x<hex>/<space>:<hex> address. Use get_address_spaces on multi-space targets. Omit for "
        "bulk hashing via offset/limit/filter.",
    ),
    (
        "Skip the batched decompiler path and rename each variable on its own via HighFunctionDBUtil. Slower, but"
        " it does not commit parameters to the database or suppress events, and it reports per-variable failures "
        "instead of losing the whole batch. Use it when the batch path fails or renames the wrong symbol; the "
        "response carries \"method\": \"individual\".",
        "Use slower per-variable HighFunctionDBUtil renames: no parameter commit or event suppression, "
        "per-variable failures, method=individual. Use when batch renaming fails or targets the wrong symbol.",
    ),
    (
        "JSON array of field objects, exactly the shape create_struct takes: required keys name and type, "
        "optional offset as a decimal BYTE offset. field_name/fieldName, field_type/fieldType/data_type/dataType "
        "and field_offset/fieldOffset/off are accepted as alternates. Field names get the project's Hungarian "
        "prefix applied automatically.",
        "JSON [{name,type,offset?},...]; offset is decimal bytes. Aliases: field_name/fieldName, "
        "field_type/fieldType/data_type/dataType, field_offset/fieldOffset/off. Applies project Hungarian "
        "prefixes.",
    ),
    (
        "Full C signature as one string, e.g. int __fastcall Foo(int nCount, char *pszName). The NAME in it is "
        "parsed and then discarded — it does NOT rename the function, call rename_function for that. A calling "
        "convention written here is only recognised before the first '(', so one inside a callback parameter type"
        " survives untouched.",
        "Full C signature, e.g. int __fastcall Foo(int nCount). Name is discarded; rename_function separately. "
        "Calling conventions are recognized only before the first (, leaving callback types untouched.",
    ),
    (
        "JSON array of field objects. Required keys: name, type. Optional key: offset as a decimal byte offset. "
        "Alternate keys are accepted: field_name/fieldName, field_type/fieldType/data_type/dataType, "
        "field_offset/fieldOffset/off. Example: "
        "[{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},{\"name\":\"pNext\",\"type\":\"void *\",\"offset\":4}]",
        "JSON [{name,type,offset?},...]; offset is decimal bytes. Aliases: field_name/fieldName, "
        "field_type/fieldType/data_type/dataType, field_offset/fieldOffset/off.",
    ),
    (
        "New data type, resolved recursively (pointer chains, array syntax such as dword[8], existing struct/enum"
        " names). A type starting with `undefined` is REJECTED whatever the current type is — swapping one "
        "undefined width for another is a no-op, not documentation. For 'this', a bare struct name is "
        "auto-suffixed with ' *'.",
        "Resolved recursively: pointer chains, arrays (dword[8]), existing structs/enums. Types starting "
        "undefined are rejected. For this, bare struct names gain *.",
    ),
    (
        "JSON object mapping member name to integer value, e.g. {\"UNIT_PLAYER\": 0, \"UNIT_MONSTER\": 1}. Values may"
        " be numbers, decimal strings, or 0x-prefixed hex strings; floats and non-numeric strings are rejected. "
        "Member names are checked for UPPERCASE_SNAKE_CASE and any complaint comes back as a warning, not a "
        "failure.",
        "JSON member-name -> integer object. Accepts numbers, decimal strings or 0x hex strings; rejects "
        "floats/non-numeric strings. UPPERCASE_SNAKE_CASE violations warn.",
    ),
    (
        "Instruction addresses to pull context around. Accepts a JSON array of address strings or one "
        "comma-separated string, each in the usual 0x<hex> or <space>:<hex> form. The result is keyed by the "
        "exact string you sent, and an address with no instruction at it gets its own error entry rather than "
        "failing the batch.",
        "JSON address-string array or comma-separated string (0x<hex>/<space>:<hex>). Results keyed by exact "
        "input; missing instructions produce per-address errors.",
    ),
    (
        "Type to apply at the address. Any name the resolver understands: a built-in (uint, char *), an existing "
        "struct/enum/typedef name, a pointer chain (int**), or array syntax basetype[count] such as dword[10]. "
        "Create the type first with create_struct / create_enum / create_derived_type if it does not exist yet.",
        "Resolvable built-in, existing struct/enum/typedef, pointer chain or basetype[count] array. Create "
        "missing types first (create_struct/create_enum/create_derived_type).",
    ),
    (
        "JSON object whose required keys depend on `classification`: PRIMITIVE needs {\"type\": \"dword\"}; STRUCTURE"
        " needs a name plus a fields array of {name, type} objects; ARRAY needs count plus either element_type or"
        " element_struct; STRING takes an optional type. It must be an OBJECT — a JSON string is rejected.",
        "JSON OBJECT, not encoded string. PRIMITIVE: {type}; STRUCTURE: {name,fields:[{name,type}]}; ARRAY: "
        "{count,element_type} or {count,element_struct}; STRING: optional type.",
    ),
    (
        "Block length in bytes. Omit (or 0) when byte content is supplied to size the block to the content "
        "exactly. If larger than the content, the remainder is filled with fill_byte. Must be positive when no "
        "content is supplied. Outside an overlay, address..address+size-1 must not overlap an existing block.",
        "Length in bytes; omitted/0 uses supplied content length. Larger sizes pad with fill_byte. Positive "
        "required without content. Non-overlay range must not overlap existing blocks.",
    ),
    (
        "Create the block in a new overlay address space instead of the program's physical memory. Use this to "
        "map a region that deliberately overlaps existing blocks (bank switching, ROM shadowing); the overlap "
        "check is skipped and the response reports the generated overlay space in address_space.",
        "Create a new overlay address space, allowing overlap with physical blocks (banking/ROM shadowing). "
        "Returns generated name in address_space.",
    ),
    (
        "Type the new one is built on: what a typedef resolves to, the array's element type, or the pointee. "
        "Resolution is recursive, so pointer chains (int**), array syntax (dword[16]), well-known C types and "
        "existing struct/enum names all work; `void` is Ghidra's void type.",
        "Typedef target, array element or pointee. Recursively resolves pointers, arrays, C types and existing "
        "structs/enums; void is supported.",
    ),
    (
        "Lines of the caller's decompilation to return per call site, centred on the call. 1 is the call line "
        "alone; the default 3 adds the line above and below, which is usually where the guard and the use of the "
        "result live. Clamped to 1-21; costs no extra decompilation.",
        "Caller decompilation lines per call site, centered on call; 1 = call only, default 3. Clamped 1-21; no "
        "extra decompilation.",
    ),
)

# FastMCP dedents static docstrings; captured schemas may retain indentation.
DESCRIPTION_REPLACEMENTS += tuple(
    (dedent(verbose), concise) for verbose, concise in DESCRIPTION_REPLACEMENTS if "\n" in verbose
)


# Further exact rewrites; keep compact data rows in this existing table.
DESCRIPTION_REPLACEMENTS += (
    ("Optional object mapping a tag name to its description. Used only for a tag this call creates; a tag that already exists keeps its description (change one with set_function_tag_comment).", "Map tag names to descriptions for newly created tags only. Existing descriptions need set_function_tag_comment."),
    ("Name for the new field. The project's Hungarian prefix is applied automatically from field_type, so the stored name can differ from what you send — the response reports the name actually used, and remove_struct_field accepts either form.", "Name; field_type adds project Hungarian prefix. Response reports stored name; remove_struct_field accepts either form."),
    ("BYTE offset to place the field at. -1 (the default) appends to the end. A non-negative offset OVERWRITES whatever occupies that range rather than shifting later fields, and grows the struct when it lies at or past the current end.", "Byte offset; -1 (default) appends. >=0 OVERWRITES the occupied range without shifting fields; grows struct if needed."),
    ("How many BYTES forward from `address` to walk while collecting references and hunting the next named symbol (default 1024). String detection only ever reads the first 256 bytes of whatever the scan covered.", "Bytes to scan forward from address for refs/boundary (default 1024). String detection reads only the first 256 scanned bytes."),
    ("True (the default) adds xref_map: a per-byte map from address to the sources referencing it, for every byte in the scanned range that has at least one. False keeps the aggregate counts and drops the map, which is most of the payload on a heavily referenced region.",
     "Default true: add xref_map of referenced byte addresses to their sources. False omits this potentially large map, keeping aggregate counts."),
    ("True (the default) stops the forward scan at the first named symbol that is not a DAT_ autogen, so the region ends where the next documented global begins. False scans the full max_scan_bytes whatever symbols it crosses.", "Default true: stop at first named non-DAT_ symbol. False scans all max_scan_bytes across symbols."),
    ("True (the default) adds `xrefs` — the sources referencing the entry point — capped at the first 100. `xref_count` counts what was listed, so a value of exactly 100 may mean 'more than 100'; use get_xrefs_to for the true total.", "Default true: entry-point xrefs, capped at 100. xref_count counts listed refs; 100 may mean more. Use get_xrefs_to for true total."),
    ("True (the default) adds `disassembly`: address plus MNEMONIC only, no operands, capped at the first 100 instructions of the body. Use disassemble_function when you need operands or the whole body.", "Default true: first 100 body instructions, addresses and mnemonics only. For operands/full body use disassemble_function."),
    ("Optional label for the structure being analysed. It does NOT select the type — that comes from the data already applied at `address` — and is only echoed back; omit it to use the applied type's own name.", "Echoed label only; type comes from data applied at address. Omit to use that type name."),
    ("Which shape to build, matched case-sensitively against exactly PRIMITIVE, STRUCTURE, ARRAY or STRING. Any other value applies NO type at all and the call falls through to the rename and comment steps.", "Case-sensitive: PRIMITIVE|STRUCTURE|ARRAY|STRING. Other values apply NO type; rename/comment steps still run."),
    ("Optional PRE comment for the address. Unlike the plate-comment tools, this one DOES turn the two-character escapes for newline, tab and return into real whitespace, so an escaped string arrives as multiple lines.", "Optional PRE comment; converts escaped newline/tab/return sequences to real whitespace (unlike plate-comment tools)."),
    ("Bulk mode: array of objects, each taking the same fields as the top level (address, name, prototype, ...). When non-empty, the top-level fields are ignored and the response lists one result per entry. One entry failing does not stop the rest.",
     "Array of top-level-shaped objects ({address,name,prototype,...}). Nonempty overrides top-level fields. Returns per-entry results; failures do not stop later entries."),
    ("Array of {ordinal, name, type} as get_function_documentation exports them. A generic name (param_N) and an undefined type are skipped, so an export applies back without reverting anything. Reported under variable_renames and variable_types.", "Array of {ordinal,name,type} from get_function_documentation. Skips param_N names and undefined types. Reports variable_renames/variable_types."),
    ("Plate comment for the function. Pass real multi-line text: an escaped newline sequence is stored as those two literal characters, not as a line break. Empty is skipped; clear one with set_comment.", "Plate text; use real newlines (escaped sequences stay literal). Empty skips; clear with set_comment."),
    ("Array of {address | relative_offset, pre_comment, eol_comment}: PRE (the decompiler's line above) and EOL (the listing's trailing) comments. relative_offset counts from the function entry, as the export writes it. An empty string clears that comment.",
     "Array of {address|relative_offset,pre_comment,eol_comment}. Offset from function entry. PRE = decompiler line above; EOL = listing trailing. Empty string clears."),
    ("JSON object mapping each parameter's CURRENT name to its new name. Keys must match exactly; an entry naming a parameter that does not exist is ignored silently, and parameters_renamed in the response reports how many actually landed.", "Map exact current parameter names to new names. Unknown parameters silently skipped; parameters_renamed counts successes."),
    ("Optional new return type: a type name, a pointer (char*) or an array (int[4]), resolved like every other tool's type argument. A type that cannot be resolved refuses the whole call before anything is renamed.", "Optional type name, pointer (char*) or array (int[4]). Unresolvable type rejects the entire call before any renames."),
    ("JSON array of {address, comment} objects setting EOL comments — the trailing comment on a listing line. Same per-entry address rules and the same silent skip as decompiler_comments; an empty comment string clears that address's EOL comment.",
     "JSON [{address,comment},...] for listing EOL comments. Uses each entry address; missing keys/invalid addresses silently skipped. Empty comment clears EOL."),
    ("Optional name for the new function; leave empty to keep Ghidra's generated FUN_<address>. Written directly, so the naming-quality gate does not run here — use rename_function if you want it to.", "Optional name; empty keeps FUN_<address>. Bypasses naming-quality gate; use rename_function for validation."),
    ("True (the default) disassembles the entry address first when no instruction exists there, which is what lets you create a function over raw undefined bytes. False requires the address to be disassembled already; function creation fails otherwise.",
     "Default true: disassemble entry if needed, allowing function creation on undefined bytes. False requires existing instructions or creation fails."),
    ("JSON [{\"name\":\"dwId\",\"type\":\"uint\"},...]. Only types are used; names discarded. Plain comma/colon splitting cannot handle types containing either. Unresolvable parameter types are silently dropped.", "JSON [{name,type},...]; names discarded. Comma/colon splitting cannot handle types containing either; unresolved types silently dropped."),
    ("Marks the block volatile (default false): its contents can change outside program flow, so the decompiler stops folding repeated reads away. Set this for MMIO and peripheral register regions.", "Default false. Set true for MMIO/peripherals; prevents decompiler folding repeated reads that may change outside program flow."),
    ("Block contents as a hex string, e.g. \"deadbeef\" or \"de ad be ef\". Whitespace, commas and a leading 0x are ignored. Supplying content forces initialized=true. Max 16777216 decoded bytes. Mutually exclusive with bytes_base64.", "Hex contents (deadbeef or de ad be ef); ignores whitespace, commas, leading 0x. Forces initialized=true. Max 16777216 decoded bytes; excludes bytes_base64."),
    ("Block contents as a standard base64 string — preferred over bytes_hex for large or fully binary payloads. Supplying content forces initialized=true. Max 16777216 decoded bytes. Mutually exclusive with bytes_hex.", "Standard base64 contents; preferred for large/binary data. Forces initialized=true. Max 16777216 decoded bytes; excludes bytes_hex."),
    ("Create an initialized block (real bytes backed by the program database) rather than an uninitialized one. Implied true when byte content is supplied. An initialized block is capped at 268435456 bytes; leave it false for larger MMIO apertures.", "Database-backed bytes; forced true by supplied content. Initialized size cap: 268435456 bytes. Use false for larger MMIO ranges."),
    ("Number of BYTES to disassemble from start_address, as an alternative to end_address; end_address wins when both are given. 0 (the default) with no end_address auto-detects the run of undefined bytes and stops at a 100-byte safety cap.", "Bytes from start_address; end_address takes precedence. Default 0 without end_address scans undefined bytes, capped at 100 bytes."),
    ("True (the default) refuses to disassemble outside memory blocks marked executable, which stops a stray address turning data into instructions. Set false only for code that genuinely lives in a non-execute block.", "Default true: require executable memory blocks. False permits disassembly in non-executable blocks; use only for code there."),
    ("Cap on number of instructions returned when include_instructions is true. Protects against runaway payload for large ranges; if the actual count exceeds this, the response sets truncated=true and instructions_total reports the real count.", "Returned-instruction cap when include_instructions=true. Overflow sets truncated=true; instructions_total reports full count."),
    ("JSON [{\"address\":\"0x408300\",\"length\":16},...] to read emulator memory AFTER execution. Required to observe in-place mutations: emulator memory is isolated; subsequent read_memory sees original program bytes.", "JSON [{\"address\":\"0x408300\",\"length\":16},...] reads emulator memory after execution. Required to see mutations; later read_memory sees original program bytes."),
    ("Maximum matches returned, highest similarity first (default 20). It truncates the result only: every candidate in the target program is still scored, so a small limit does not make the call cheaper.", "Maximum matches, highest similarity first (default 20). All target candidates are still scored; lower limit saves output, not compute."),
    ("How many instructions to include on EACH side of every source address (default 5), so the window is up to 2n+1 instructions. The walk stops early at the start or end of the listing.", "Instructions on EACH side of each source (default 5), up to 2n+1 total; stops at listing boundaries."),
    ("Address of the external location, as 0x<hex> (default space) or <space>:<hex> (e.g. mem:1000). This is the selector: matching is done on the address alone, so a dll_name with no address finds nothing.", "Selector address: 0x<hex> or <space>:<hex> (mem:1000). Matching uses address alone; dll_name without address finds nothing."),
    ("External library name (as list_program_items(kind=imports) or kind=external_locations reports it) to scope the search to. Omit to scan every library. It narrows the search only — it cannot select an entry by itself.", "Library from list_program_items(kind=imports|external_locations). Omit for all libraries. Narrows search; cannot select without address."),
    ("Bulk mode: number of matching functions to skip before this page starts; 0 begins at the first. The filter is applied before the skip, so paging is stable only within one filter value.", "Bulk matching functions to skip (0 = first), after filtering. Keep filter fixed while paging."),
    ("Include each caller's decompiled call-site line. Costs one decompilation per unique caller (~43ms); set false for the cheapest possible bundle. Ignored unless call_context is requested (explicitly or via an empty fields=).", "Decompile each unique caller (~43ms) for call-site lines. False avoids that cost. Ignored unless fields includes call_context or is empty."),
    ("Comma-separated addresses for the many-at-once form. The result is a map of address to its reference list, and an address that does not resolve gets an empty list rather than failing the whole call.", "Comma-separated bulk addresses; returns address-to-refs map. Unresolvable addresses yield empty lists, not whole-call failure."),
    ("Replacement field name. Leave empty to keep the current name and only retype. The project's Hungarian prefix is applied automatically from the field's type, so the stored name can differ from what you send.", "Empty keeps current name (retype only). Project Hungarian prefix applies from field type; stored name may differ."),
    ("For kind=label: the current label name at the address given by target. When target is omitted this is used as the target instead, for callers migrated from rename_global_variable(old_name, new_name).", "For kind=label: current label at target address. If target omitted, old_name supplies target."),
    ("Per-call override for the naming-quality gate: 'enforce' rejects a convention miss, 'warn' applies the name and returns the miss as a warning, 'off' skips the check. Omit to use the project/global setting.", "Naming gate: enforce = reject convention miss; warn = apply with warning; off = skip. Omit for project/global setting."),
    ("JSON object mapping each variable's CURRENT decompiler name to its new name. Matching happens against the decompiler's high-level symbols, so use the names get_functions reports (parameters, locals, decompiled_code), not the raw listing's.", "Map CURRENT decompiler variable names to new names. Use get_functions parameters/locals/decompiled_code names, not listing symbols."),
    ("Label echoed back in each match's `encoding` field. It does NOT filter: every defined string is searched whatever you pass here, and matches that carry no value report the literal string `ascii`.", "Echoed encoding label, NOT a filter; all defined strings searched. Matches without a value report ascii."),
    ("Bookmark category, free text; empty or omitted becomes the literal `Note`. An existing bookmark at this address in the SAME category is replaced, while a different category adds a second bookmark. Everything here is created under Ghidra's Note bookmark type.",
     "Free-text category; empty/omitted = Note. Replaces existing bookmark at same address/category; other categories coexist. Bookmark type is always Note."),
    ("True marks the function non-returning: its call sites become CALL_TERMINATOR, so control-flow analysis and the decompiler stop showing execution continuing past the call. False clears that back to an ordinary returning function. Required — there is no default.",
     "Required; no default. True sets CALL_TERMINATOR at call sites and stops control-flow/decompiler continuation. False restores ordinary returning calls."),
    ("Convention to apply — __cdecl, __stdcall, __fastcall, __thiscall and whatever else list_calling_conventions reports for this program's language. When set it OVERRIDES the convention written into the prototype string; omit to use whatever the prototype says.",
     "Convention from list_calling_conventions (e.g. __cdecl, __stdcall, __fastcall, __thiscall). Overrides prototype convention; omit to keep prototype value."),
    ("Plate comment for the address. First line must be a meaningful one-line summary (≥4 words). Optional sectioned details (Used by:, Layout:, Source:, Bitfield:) follow when applicable. Pass empty to leave plate comment unchanged.", "Plate comment; meaningful first-line summary (>=4 words). Optional Used by:/Layout:/Source:/Bitfield: details. Empty leaves unchanged."),
    ("Entry address of the function that owns the variable. Accepts 0x<hex> (default space) or <space>:<hex> (e.g., mem:1000, code:ff00); use get_address_spaces first on targets that are not address-space-agnostic.", "Owning function entry: 0x<hex> or <space>:<hex> (mem:1000, code:ff00). Discover spaces with get_address_spaces on multi-space targets."),
    ("Local or parameter to retype, named exactly as the decompiler shows it (get_functions fields=parameters,locals lists them). The literal value 'this' is special-cased and routes to set_function_this_type.", "Exact decompiler local/parameter name (get_functions fields=parameters,locals). this routes to set_function_this_type."),
    ("JSON object mapping old variable names to {name, type} objects. Both fields optional: omit 'type' to rename only, omit 'name' to retype only. Example: {\"local_8\": {\"name\": \"dwFlags\", \"type\": \"uint\"}, \"local_c\": {\"type\": \"int\"}}", "JSON {old_name:{name?,type?},...}. Omit type to rename only; omit name to retype only."),
    ("Optional address. Omit to check type existence only; provide to validate applicability at that address (memory range/alignment/conflicts). Accepts 0x<hex> (default space) or <space>:<hex> (e.g., mem:1000, code:ff00).", "Omit for type-existence check; supply for memory/alignment/conflict checks. 0x<hex> or <space>:<hex> (mem:1000, code:ff00)."),
    ("Restore a Ghidra .gar archive into a fresh on-disk project at `parent_dir/project_name`. The open project is left alone, and the restored one is NOT opened automatically; follow up with /open_project so owner reset and project bookkeeping run via the same code path as a user-driven open. Fails loudly if the destination project already exists.",
     "Restore .gar to NEW parent_dir/project_name; fails if project exists. Leaves current project open. Then call open_project for owner reset/bookkeeping; restored project is not auto-opened."),
    ("Compute the normalized opcode hash of ONE function (function=), or of MANY in one call by omitting it: every function, paged, optionally only the documented or undocumented ones (filter=). On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.",
     "Normalized opcode hash: function for one; omit for all, paginated by documentation filter. Multi-space addresses: mem:1000."),
    ("Get cross-references to ONE address, or to MANY at once (addresses=comma-separated), which returns a map keyed by the address you asked for. Replaces the former get_bulk_xrefs. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.",
     "Read xrefs to one address, or addresses=comma-separated for an address-to-refs map. Multi-space addresses: mem:1000."),
    ("Modify a field in a structure: retype it (new_type, which also embeds a struct by value, e.g. Rectangle inside LayoutNode), rename it (new_name), or both. Fields can be identified by name or by offset (for unnamed fields). For layout size changes (grow/shrink padding), use resize_struct instead of manual delete+create.",
     "Retype (new_type, including embedded structs by value), rename (new_name), or both. Select field by name/offset (including unnamed). For padding/size changes use resize_struct."),
    ("Replace a structure in one step: optionally remove an existing same-named type, then create with fields JSON (same shape as create_struct). Use when resize_struct cannot apply or you are rebuilding layout from get_struct_layout export. Set force=true to delete a non-stub type that is not referenced.",
     "Replace struct with fields JSON (create_struct shape), optionally removing same-name type first. Use for layouts resize_struct cannot handle or get_struct_layout exports. force=true deletes an unreferenced non-stub type."),
    ("Open a Ghidra project: local .gpr/directory, or ghidra://host[:port]/repo (persistent shared project; does not auto-open repo files — max ~5 shared programs). GUI mode adds optional `headless` (default true) and `program`; the headless server ignores those. Local tree mirrors YOUR working copy.",
     "Open local .gpr/directory or ghidra://host[:port]/repo. Shared repo files are not auto-opened (~5 shared programs max); local tree is your working copy. GUI headless=true suppresses CodeBrowser; headless=false launches it for program. Headless server ignores both inputs."),
    ("Open an existing Ghidra project (.gpr file or directory). GUI mode adds optional `headless` (default true) to suppress auto-launching CodeBrowser, and optional `program` to auto-launch CodeBrowser for a specific file when headless=false. Headless server ignores the extra params.",
     "Open local .gpr/directory. GUI headless=true (default) suppresses CodeBrowser; headless=false launches it for optional program. Headless server ignores both inputs."),
    ("Move a program file to a different folder in the project, preserving all analysis and documentation. Refuses when the program has unsaved changes -- call save_program first -- rather than discarding them. A program that is open but clean is closed, moved, then reopened at its new path.",
     "Move project program, preserving analysis/docs. Refuses unsaved changes; save_program first. Clean open programs are closed, moved and reopened at the new path."),
    ("Move a program file to a different folder in the project, preserving analysis and documentation. Refuses on unsaved changes; closes, moves and reopens a program that is open but clean.", "Move project program, preserving analysis/docs. Refuses unsaved changes; save_program first. Clean open programs are closed, moved and reopened at the new path."),
    ("The open project: name, file count, whether it is bound to a Ghidra Server (and which repository), and which programs are open. A shared project is what /checkin_program and a checkout's content need; project_server_bound=false means local-only. On the GUI also the running tools.",
     "Open project name, file count, server/repository binding and open programs; GUI also lists running tools. project_server_bound=false is local-only; checkin_program/checkout content requires shared project."),
    ("Dump the program's language description: address spaces, registers (with parent/child/aliases/description), default symbols (with end address and isEntry/isPrimary/isVolatile flags), endianness, pointer size. For P-code emulators / ML pipelines that need the SLEIGH-level facts.",
     "Read SLEIGH language facts: address spaces, registers (parents/children/aliases/descriptions), default symbols (end address and isEntry/isPrimary/isVolatile flags), endianness and pointer size."),
    ("Dump the program's language description: address spaces, registers, default symbols, endianness, pointer size (issue #192). Use for P-code emulators / ML pipelines that need the SLEIGH-level facts. include_registers/include_default_symbols toggle expensive sections.",
     "Read SLEIGH language facts: address spaces, registers, default symbols, endianness and pointer size. include_registers/include_default_symbols toggle expensive sections."),
    ("Find gaps of undefined/unanalyzed bytes in executable memory not covered by any function body. Useful for discovering missed functions in firmware and embedded binaries. Reports each contiguous uncovered range with its size, content type, and the nearest functions on each side.",
     "Find contiguous undefined/unanalyzed executable bytes outside function bodies. Reports size, content type and nearest functions on each side."),
    ("List (address, value) entries stored in a property map, with pagination. Optionally restrict to an inclusive address range with start/end. Omit map to list the property maps instead: each one's name, value type (int|long|string|object|void) and how many addresses hold a value.",
     "Paginated property-map address/value entries; optional inclusive start/end range. Omit map for map names, value types (int|long|string|object|void) and address counts."),
    ("Validate a data type. With an address: checks applicability (memory range, alignment, conflicts) at that address. Without an address: checks only that the type exists, resolving bare names like 'int'/'DWORD'/'char *' across all categories. Replaces validate_data_type_exists.",
     "With address: check type applicability (memory range/alignment/conflicts). Without: check existence, resolving bare names (int, DWORD, char *) across categories."),
    ("Set the data type of a function variable (local OR parameter) by name at the decompiler (high-level) layer. Pass variable_name='this' to type a __thiscall/__fastcall implicit this. Replaces set_local_variable_type / set_parameter_type / set_decompiler_variable_type.", "Retype a decompiler local/parameter by name. variable_name=this sets implicit __thiscall/__fastcall this type."),
    ("Attach tags to ONE function (function + tags) OR MANY in one transaction (assignments=[{function,tags}, ...]). Tags are comma-separated and created on the fly (give a new tag a description with tag_comments). Replaces batch_add_function_tags and create_function_tag.",
     "Attach comma-separated tags to one function, or assignments=[{function,tags},...] atomically. Creates missing tags; tag_comments describes new tags."),
    ("Grow or shrink an existing structure by total byte size. Defined fields whose end offset fits within new_size are preserved; growth pads with undefined filler. Refuses shrink that would clip defined fields unless force=true. See docs/STRUCT_RESIZE_WORKFLOW.md.",
     "Resize struct in bytes; preserve fields fitting new_size, pad growth with undefined filler. Refuses clipping defined fields unless force=true. See docs/STRUCT_RESIZE_WORKFLOW.md."),
    ("What is checked out under a file or folder of the open project, locally or on the server (with the holders' users and checkout ids). modified_since_checkout says whether a checkout holds uncommitted work, which is what decides if it is safe to release.",
     "List local/server checkouts under project file/folder, including users and checkout IDs. modified_since_checkout identifies uncommitted work affecting safe release."),
    ("Set a value at an address in a property map. The value is coerced to the map's type (int/long/string); 'void' maps ignore the value and just tag the address. Create the map first with create_property_map. Call save_program to persist.", "Set map value at address, coerced to int/long/string; void maps tag presence only. Requires create_property_map first. save_program persists."),
    ("Detach tags from ONE function (function + tags) OR MANY in one transaction (assignments=[{function,tags}, ...]). Does not delete the program-wide tag definition — use delete_function_tag for that. Replaces batch_remove_function_tags.", "Detach tags from one function, or assignments=[{function,tags},...] atomically. Keeps program-wide tag definitions; delete_function_tag removes those."),
    ("Create a user property map to store typed values keyed by address. Types: int, long, string, void (address-presence tag). Use a string map holding JSON to store arbitrary structured per-address data. Call save_program to persist.", "Create address-keyed map: int|long|string|void (presence tag). Use string JSON values for structured data. save_program persists."),
    ("Read all options in a program option group with types, current values, defaults, and descriptions. Omit group to list the option groups instead (e.g. 'Program Information', 'Analyzers', 'Decompiler'), each with its option count.", "Read group options with types/current/default values/descriptions. Omit group to list groups (Program Information, Analyzers, Decompiler) with option counts."),
    ("Set a typed program option. If the option already exists its type is reused; otherwise pass type (string|int|long|double|float|boolean). New/custom options are created on demand. Call save_program to persist.", "Set typed option; existing type reused, else pass string|int|long|double|float|boolean. Creates custom options as needed. save_program persists."),
    ("Find data types by name or path pattern, category and kind, one record per type (name, kind, category, size, path). With categories=true, list the category paths instead. With no filter it lists every type.", "Find by name/path pattern, category and kind; returns name/kind/category/size/path. categories=true lists category paths. No filter lists all types."),
    ("On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", "Multi-space addresses: prefix with space name (mem:1000)."),
    ("On programs with multiple address spaces (e.g., embedded targets), prefix function_address with the space name (mem:1000) to avoid ambiguous resolution.", "Multi-space addresses: prefix with space name (mem:1000)."),
    ("On programs with multiple address spaces, prefix addresses with the space name (mem:1000).", "Multi-space addresses: prefix with space name (mem:1000)."),
)
