# Ghidra Scripts

This directory contains scripts that run **directly inside Ghidra** (not via MCP bridge).

## Script Types

### Java Scripts

- **ClearCallReturnOverrides.java** - Clears incorrect CALL_RETURN flow overrides that prevent proper control flow analysis
- **DocumentFunctionWithClaude.java** - Documents the current function by calling Claude AI with comprehensive plate comment prompt (Keybinding: Ctrl+Shift+D)
- **ImportMSDLPDB.java** - Downloads the matching PDB for the current program from
  Microsoft's symbol server and applies it via Ghidra's PDB Universal Analyzer.
  One-time Ghidra setup: `Edit > Symbol Server Config` → point at
  `https://msdl.microsoft.com/download/symbols` with a local cache dir.
  Skips gracefully (empty JSON result) when the binary has no `PdbInformation`
  header — no `/DEBUG` link flag, common for third-party DLLs. PDB covers the
  symbols Microsoft published (CRT / MSVCRT / MFC); a heuristic library-code
  detector catches the rest.

## How to Use These Scripts

### Method 1: Ghidra Script Manager (Recommended)

1. Open Ghidra
2. Go to **Window → Script Manager**
3. Click the **"Manage Script Directories"** button (folder icon)
4. Add this directory: `<repo>/ghidra_scripts`
5. Click **Refresh** in Script Manager
6. Scripts will appear in the list - double-click to run

### Method 2: Copy to Ghidra's User Script Directory

Copy the `.java` files from this directory into your Ghidra user script
directory, then refresh the Script Manager in Ghidra.

## Script Annotations

Ghidra scripts use special annotations:

- `@author` - Script author
- `@category` - Category in Script Manager (e.g., Analysis, Data)
- `@keybinding` - Optional keyboard shortcut
- `@menupath` - Menu location (e.g., Tools.Clear CALL_RETURN Overrides)
- `@toolbar` - Adds toolbar button

## Development Notes

### Java Scripts

Must extend `GhidraScript` class and have these imports:

```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
```

### MCP script execution

The GUI extension and headless MCP server execute Java scripts only.
`run_script_inline` accepts Java statements or a complete `GhidraScript` class
and discards its isolated temporary bundle after execution. Use
`run_ghidra_script` for persistent `.java` files. Python/Jython scripts are
excluded from listing and filename resolution, and cannot be run through
these MCP endpoints. The external Python MCP bridge is unaffected.

## Difference from /scripts Directory

- **`/ghidra_scripts`** - Run inside Ghidra GUI (this directory)
- **repo utilities / MCP bridge** - Run externally from Python-based repo tools

## Resources

- [Ghidra Script Development Guide](https://ghidra.re/courses/GhidraClass/Intermediate/Scripting.html)
- [GhidraScript API Documentation](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)
