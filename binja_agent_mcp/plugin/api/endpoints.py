# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
from typing import Dict, Any, List, Optional
import functools
import re
import traceback
import binaryninja as bn
from ..core.binary_operations import BinaryOperations
from ..core.binary_operations import _basename as _sel_basename
from ..core.binary_operations import _is_abs_path as _sel_is_abs_path
from ..core.binary_operations import _name_key as _sel_name_key
from ..core.binary_operations import _norm_path as _sel_norm_path
from ..core import request_context as rc


# --- /binaries selectors ---------------------------------------------------------------------------
# The listing advertises only selectors that name THEIR OWN entry in BOTH resolvers: the strict
# per-call resolver (BinaryOperations.resolve_binary, every `binary=` parameter) and the legacy
# /selectBinary (select_binary below -> BinaryOperations.select_view): 'view:<id>', the bare view
# id, a unique absolute filename and a unique basename. The 1-based listing ordinal '#<n>' is still
# ACCEPTED by both, but not advertised: it is positional, so it names another binary after one is
# opened or closed. Paths and names are compared with the resolver's own helpers (imported above),
# so the listing and the resolver agree on every platform.
_RE_SEL_ORDINAL = re.compile(r"^#[0-9]+$")
_RE_SEL_VIEW_ID = re.compile(r"^(?:view|v):([0-9]+)$", re.IGNORECASE)
# Shapes resolve_binary reads BEFORE a path/basename (view id, ordinal, sha256, sha256 prefix):
# a basename of such a shape is never advertised (it would name something else, or force hashing).
_RE_SEL_GRAMMAR_SHAPED = re.compile(
    r"^(?:[0-9]+|#[0-9]+|(?:view|v):[0-9]+|[0-9a-fA-F]{12,64})$",
    re.IGNORECASE,
)


# --- generic verb routes (binja-agent-mcp addition) ------------------------------------------------
# The HTTP server's route hook (MCPRequestHandler._try_route) asks route_for(method, path) BEFORE
# any legacy route or loaded-binary check. A routed path is answered by _run_verb with a JSON
# envelope: success {ok:true, verb, result, truncated, next_offset, warnings, limits}; failure
# {ok:false, verb, error, error_code, candidates?}. The verbs live in core/expert_ops.py
# (VERB_FUNCS), which is imported lazily so a broken module answers 501 UNSUPPORTED_API instead of
# breaking the legacy routes.
ROUTES_GET = {
    "/x/serverInfo": "server_info",
    "/x/binaryInfo": "binary_info",
    "/x/functionStatus": "function_status",
    "/x/decompile": "decompile",
    "/x/ilSearch": "il_search",
    "/x/ssaDef": "ssa_def",
    "/x/ssaUses": "ssa_uses",
    "/x/backwardSlice": "backward_slice",
    "/x/possibleValues": "possible_values",
    "/x/branchDependence": "branch_dependence",
    "/x/cfg": "cfg",
    "/x/dominators": "dominators",
    "/x/reachable": "reachable",
    "/x/callers": "callers",
    "/x/callees": "callees",
    "/x/callPaths": "call_paths",
    "/x/returnCheck": "return_check",
    "/x/sinks": "sinks",
    "/x/undominatedSinks": "undominated_sinks",
    "/x/stackFrame": "stack_frame",
    "/x/handlerSlice": "handler_slice",
    "/x/resolveEntity": "resolve_entity",
    "/x/bytesAt": "bytes_at",
    "/x/xrefs": "xrefs",
    "/x/debugInfoStatus": "debug_info_status",
    "/x/uninitReads": "uninit_reads",
    "/x/resolveDispatch": "resolve_dispatch",
    "/x/ndrDecode": "ndr_decode",
    "/x/interprocSlice": "interproc_slice",
    "/x/compute": "compute",
}

# POST-only routes (mutating or large-body verbs); never reachable by GET.
ROUTES_POST_ONLY = {
    "/x/batch": "batch",
    "/x/closeBinary": "close_binary",
    "/x/loadBinary": "load_binary",
}

# POST accepts every GET path as well (long parameters can travel in a JSON body).
ROUTES_POST = dict(ROUTES_GET)
ROUTES_POST.update(ROUTES_POST_ONLY)

# Destructive verbs that must name their target explicitly (never the implicit global selection).
_EXPLICIT_BINARY_VERBS = frozenset({"close_binary"})


def _plain_envelope(verb, out):
    """make_envelope() equivalent used when expert_ops.make_envelope is missing."""
    out = out if isinstance(out, dict) else {}
    return {
        "ok": True,
        "verb": verb,
        "result": out.get("result"),
        "truncated": bool(out.get("truncated", False)),
        "next_offset": out.get("next_offset"),
        "warnings": list(out.get("warnings") or []),
        "limits": dict(out.get("limits") or {}),
    }


def _plain_error_envelope(verb, e):
    """error_envelope() equivalent used when expert_ops is not importable (or itself fails)."""
    code = getattr(e, "code", None)
    if not isinstance(code, str) or not code:
        code = "INTERNAL"
    msg = getattr(e, "message", None)
    if not isinstance(msg, str) or not msg:
        msg = str(e) or e.__class__.__name__
    env = {"ok": False, "verb": verb, "error": msg[:2000], "error_code": code}
    extra = getattr(e, "extra", None)
    if isinstance(extra, dict):
        for k in ("candidates", "available"):
            v = extra.get(k)
            if v:
                try:
                    env[k] = list(v)[:50]
                except Exception:
                    pass
    return env


class BinaryNinjaEndpoints:
    # Exposed on the class as well, for introspection by tests and tooling.
    ROUTES_GET = ROUTES_GET
    ROUTES_POST = ROUTES_POST
    ROUTES_POST_ONLY = ROUTES_POST_ONLY

    def __init__(self, binary_ops: BinaryOperations):
        self.binary_ops = binary_ops

    def get_entry_points(self) -> List[Dict[str, Any]]:
        """Get entry point(s) for the current binary"""
        return self.binary_ops.get_entry_points()

    # -------- Multi-binary helpers --------
    def _format_binary_listing(self, raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize binary listing entries with ordinal, view id, basename, ownership and selectors.

        `id` stays the 1-based ordinal (backcompat). `owned` is copied from list_open_binaries.
        `selectors` lists only selectors that name THIS entry in both resolvers (see the /binaries
        selectors note at the top of this module): 'view:<id>' (internal view id), the bare view id,
        the absolute filename when no other entry has the same normalized path, and the basename when
        no other entry has the same basename (compared like the resolver: without case on Windows). Two
        sessions of one file, or two same-named files, are therefore told apart by their view id only.
        resolve_binary also matches a .bndb's original_filename, so a database open next to its own
        image can make that path/basename answer 409 AMBIGUOUS there (never another binary).
        """
        items = list(raw or [])
        path_count: Dict[str, int] = {}
        base_count: Dict[str, int] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            fn = it.get("filename")
            if not fn:
                continue
            np_ = _sel_norm_path(fn)
            if np_:
                path_count[np_] = path_count.get(np_, 0) + 1
            nb = _sel_name_key(_sel_basename(fn))
            if nb:
                base_count[nb] = base_count.get(nb, 0) + 1
        formatted: List[Dict[str, Any]] = []
        for ordinal, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue    # keep the ordinals aligned with resolve_binary's '#<n>' (list index + 1)
            filename = item.get("filename")
            view_id = str(item.get("id") or "")
            basename = _sel_basename(filename) if filename else None
            entry: Dict[str, Any] = {
                "id": str(ordinal),
                "view_id": view_id,
                "filename": filename,
                "basename": basename,
                "active": bool(item.get("active")),
                "owned": item.get("owned"),
            }
            candidates: List[Optional[str]] = []
            if view_id.isdigit():
                candidates.append("view:" + view_id)
                candidates.append(view_id)
            if (
                filename
                and _sel_is_abs_path(filename)
                and path_count.get(_sel_norm_path(filename), 0) == 1
            ):
                candidates.append(filename)
            if (
                basename
                and not _RE_SEL_GRAMMAR_SHAPED.match(basename)
                and base_count.get(_sel_name_key(basename), 0) == 1
            ):
                candidates.append(basename)
            selectors: List[str] = []
            for candidate in candidates:
                if candidate and candidate not in selectors:
                    selectors.append(candidate)
            entry["selectors"] = selectors
            formatted.append(entry)
        return formatted

    def list_binaries(self) -> Dict[str, Any]:
        """List managed/open binaries with sequential ids (1..N) and active flag.

        The server maintains internal keys for views; this endpoint presents
        a user-friendly, 1-based index stable under sorting by filename. Select
        an entry by one of its `selectors` ('view:<id>' always works); its bare
        `id` is the ordinal, which as bare digits both resolvers read as a VIEW
        id first, so pass it as '#<id>'.
        """
        raw = self.binary_ops.list_open_binaries()
        return {"binaries": self._format_binary_listing(raw)}

    def select_binary(self, ident: str) -> Dict[str, Any]:
        """Select the active (GLOBAL) binary.

        Legacy selectors (bare digits = an internal view id, else a 1-based listing ordinal; a full
        filename; a basename) go to BinaryOperations.select_view unchanged. The strict forms the
        /binaries listing advertises, '#<ordinal>' and 'view:<id>' / 'v:<id>' (an internal view id), are
        located by
        BinaryOperations.locate_binary, the selection half of resolve_binary (the resolver behind every
        `binary=` parameter), so an advertised selector names the same view here and there; locating
        makes no Binary Ninja analysis or content read, as befits this lock-free (scope-exempt) route;
        an unknown selector is 'Binary not found' and never falls back to another reading. A strict
        selection is made atomically and fail-closed (_select_resolved): a view closed after it was
        located is 'Binary not found', never re-selected.
        """
        s = str(ident if ident is not None else "").strip()
        if _RE_SEL_ORDINAL.match(s) or _RE_SEL_VIEW_ID.match(s):
            info = None
            try:
                # locate only: /selectBinary is scope-exempt (it takes no view lock), so it makes no Binary Ninja
                # analysis or content read (describe_view); the selection needs the view id alone.
                bv, vid = self.binary_ops.locate_binary(s)
            except rc.ApiError:
                bv, vid = None, None
            if bv is not None:
                info = self._select_resolved(bv, {"view_id": vid})
        else:
            info = self.binary_ops.select_view(ident)
        if not info:
            return {
                "error": f"Binary not found: {ident}",
                "available": self.list_binaries().get("binaries", []),
            }
        filename = info.get("filename")
        view_id = str(info.get("id") or "")
        formatted = self._format_binary_listing(self.binary_ops.list_open_binaries())
        selected_entry: Optional[Dict[str, Any]] = None
        # The view id names exactly one entry; the filename is a fallback for an id-less answer
        # only (two sessions of one file share a filename).
        for entry in formatted:
            if view_id and entry.get("view_id") == view_id:
                selected_entry = entry
                break
        if selected_entry is None and not view_id and filename:
            for entry in formatted:
                if entry.get("filename") == filename:
                    selected_entry = entry
                    break
        if not selected_entry:
            basename = _sel_basename(filename) if filename else None
            selected_entry = {
                "id": None,
                "view_id": view_id,
                "filename": filename,
                "basename": basename,
                "active": True,
                "owned": None,
                "selectors": (["view:" + view_id] if view_id.isdigit() else []),
            }
        else:
            selected_entry["active"] = True
        return {"status": "ok", "selected": selected_entry}

    def _select_resolved(self, bv, rinfo) -> Optional[Dict[str, Any]]:
        """Make the view a strict selector resolved the GLOBAL selection: atomically, fail-closed.

        locate_binary answers from a registry snapshot taken under an EARLIER _reg_lock hold, so the view may
        have been closed since (POST /x/closeBinary -> close_owned_view). Under ONE _reg_lock hold
        the resolved id must still be registered, alive and not closing, and must still hold bv's file
        session; only then does the GLOBAL selection become the REGISTERED object of that id (what the
        current_view setter would pick). The setter itself is never used here: it re-registers its
        argument, so a closed view would come back under a fresh id as a live view.
        close_owned_view clears a global selection equal to the closed view under the same lock, so a
        close that starts after this hold still clears it. Returns {id, filename} or None
        ('Binary not found').
        """
        ops = self.binary_ops
        rinfo = rinfo if isinstance(rinfo, dict) else {}
        vid = str(rinfo.get("view_id") or "")
        if bv is None or not vid:
            return None
        with ops._reg_lock:
            if not ops.is_live(vid):
                return None
            sel = ops._obj(vid)
            if sel is None or not (ops._same(sel, bv) or ops._same_session(sel, bv)):
                return None
            ops._global_view = sel
            fn = ops._filename_of(sel)
        bn.log_debug(f"Set current binary view: {fn}")
        return {"id": vid, "filename": rinfo.get("filename") or fn or None}

    def get_function_info(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a function"""
        try:
            return self.binary_ops.get_function_info(identifier)
        except Exception as e:
            bn.log_error(f"Error getting function info: {e}")
            return None

    def get_imports(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of imported functions"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        offset = max(0, offset)
        limit = max(0, limit)
        imports = []
        for sym in self.binary_ops.current_view.get_symbols_of_type(
            bn.SymbolType.ImportedFunctionSymbol
        ):
            imports.append(
                {
                    "name": sym.name,
                    "address": hex(sym.address),
                    "raw_name": sym.raw_name if hasattr(sym, "raw_name") else sym.name,
                    "full_name": sym.full_name
                    if hasattr(sym, "full_name")
                    else sym.name,
                }
            )
        return imports[offset : offset + limit]

    def get_exports(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of exported symbols"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        offset = max(0, offset)
        limit = max(0, limit)
        exports = []
        for sym in self.binary_ops.current_view.get_symbols():
            if sym.type not in [
                bn.SymbolType.ImportedFunctionSymbol,
                bn.SymbolType.ExternalSymbol,
            ]:
                exports.append(
                    {
                        "name": sym.name,
                        "address": hex(sym.address),
                        "raw_name": sym.raw_name
                        if hasattr(sym, "raw_name")
                        else sym.name,
                        "full_name": sym.full_name
                        if hasattr(sym, "full_name")
                        else sym.name,
                        "type": str(sym.type),
                    }
                )
        return exports[offset : offset + limit]

    def get_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        """Get list of C++ namespaces"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        offset = max(0, offset)
        limit = max(0, limit)
        namespaces = set()
        for sym in self.binary_ops.current_view.get_symbols():
            if "::" in sym.name:
                parts = sym.name.split("::")
                if len(parts) > 1:
                    namespace = "::".join(parts[:-1])
                    namespaces.add(namespace)

        sorted_namespaces = sorted(list(namespaces))
        return sorted_namespaces[offset : offset + limit]

    def get_defined_data(
        self, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get list of defined data variables"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        offset = max(0, offset)
        limit = max(0, limit)
        data_items = []
        for var in self.binary_ops.current_view.data_vars:
            data_type = self.binary_ops.current_view.get_type_at(var)
            value = None

            try:
                if data_type and data_type.width <= 8:
                    value = str(
                        self.binary_ops.current_view.read_int(var, data_type.width)
                    )
                else:
                    value = "(complex data)"
            except (ValueError, TypeError):
                value = "(unreadable)"

            sym = self.binary_ops.current_view.get_symbol_at(var)
            data_items.append(
                {
                    "address": hex(var),
                    "name": sym.name if sym else "(unnamed)",
                    "raw_name": sym.raw_name
                    if sym and hasattr(sym, "raw_name")
                    else None,
                    "value": value,
                    "type": str(data_type) if data_type else None,
                }
            )

        return data_items[offset : offset + limit]

    def search_functions(
        self, search_term: str, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search functions by name"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        offset = max(0, offset)
        limit = max(0, limit)
        if not search_term:
            return []

        matches = []
        for func in self.binary_ops.current_view.functions:
            if search_term.lower() in func.name.lower():
                matches.append(
                    {
                        "name": func.name,
                        "address": hex(func.start),
                        "raw_name": func.raw_name
                        if hasattr(func, "raw_name")
                        else func.name,
                        "symbol": {
                            "type": str(func.symbol.type) if func.symbol else None,
                            "full_name": func.symbol.full_name if func.symbol else None,
                        }
                        if func.symbol
                        else None,
                    }
                )

        matches.sort(key=lambda x: x["name"])
        return matches[offset : offset + limit]

    def decompile_function(self, identifier: str) -> Optional[str]:
        """Decompile a function by name or address"""
        try:
            return self.binary_ops.decompile_function(identifier)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {e}")
            return None

    def get_assembly_function(self, identifier: str) -> Optional[str]:
        """Get the assembly representation of a function by name or address"""
        try:
            return self.binary_ops.get_assembly_function(identifier)
        except Exception as e:
            bn.log_error(f"Error getting assembly for function: {e}")
            return None

    def make_function_at(self, address: str | int, architecture: str | None = None) -> Dict[str, Any]:
        """Create a function at an address (no-op if already exists).

        On invalid/unknown platform (non-default arch parameter), returns an error object with
        an exhaustive list of available platforms so clients/LLMs can choose properly.
        """
        try:
            return self.binary_ops.make_function_at(address, architecture)
        except ValueError as e:
            # Enumerate all available platforms dynamically
            platforms: list[str] = []
            try:
                plats_obj = getattr(bn, 'Platform', None)
                if plats_obj is not None:
                    try:
                        platforms = [str(getattr(p, 'name', str(p))) for p in list(plats_obj)]
                    except Exception:
                        platforms = []
            except Exception:
                platforms = []
            # Fallback list if BN enumeration fails
            if not platforms:
                platforms = [
                    'decree-x86','efi-x86','efi-windows-x86','efi-x86_64','efi-windows-x86_64','efi-aarch64','efi-windows-aarch64','efi-armv7','efi-thumb2',
                    'freebsd-x86','freebsd-x86_64','freebsd-aarch64','freebsd-armv7','freebsd-thumb2',
                    'ios-aarch64','ios-armv7','ios-thumb2','ios-kernel-aarch64','ios-kernel-armv7','ios-kernel-thumb2',
                    'linux-ppc32','linux-ppcvle32','linux-ppc64','linux-ppc32_le','linux-ppc64_le','linux-rv32gc','linux-rv64gc',
                    'linux-x86','linux-x86_64','linux-x32','linux-aarch64','linux-armv7','linux-thumb2','linux-armv7eb','linux-thumb2eb',
                    'linux-mipsel','linux-mips','linux-mips3','linux-mipsel3','linux-mips64','linux-cnmips64','linux-mipsel64',
                    'mac-x86','mac-x86_64','mac-aarch64','mac-armv7','mac-thumb2','mac-kernel-x86','mac-kernel-x86_64','mac-kernel-aarch64','mac-kernel-armv7','mac-kernel-thumb2',
                    'windows-x86','windows-x86_64','windows-aarch64','windows-armv7','windows-thumb2','windows-kernel-x86','windows-kernel-x86_64','windows-kernel-windows-aarch64',
                ]
            return {"error": str(e), "available_platforms": platforms}

    def define_types(self, c_code: str) -> Dict[str, str]:
        """Define types from C code string
        
        Args:
            c_code: C code string containing type definitions
            
        Returns:
            Dictionary mapping type names to their string representations
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If parsing the types fails
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Parse the C code string to get type objects
            parse_result = self.binary_ops.current_view.parse_types_from_string(c_code)
            
            # Define each type in the binary view
            defined_types = {}
            for name, type_obj in parse_result.types.items():
                self.binary_ops.current_view.define_user_type(name, type_obj)
                defined_types[str(name)] = str(type_obj)
                
            return defined_types
        except Exception as e:
            raise ValueError(f"Failed to define types: {str(e)}")

    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> Dict[str, str]:
        """Rename a variable inside a function
        
        Args:
            function_name: Name of the function containing the variable
            old_name: Current name of the variable
            new_name: New name for the variable
            
        Returns:
            Dictionary with status message
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or variable cannot be renamed
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
            
        # Find the function by name
        function = self.binary_ops.get_function_by_name_or_address(function_name)
        if not function:
            raise ValueError(f"Function '{function_name}' not found")
            
        # Try to rename the variable
        try:
            # Get the variable by name and rename it
            variable = function.get_variable_by_name(old_name)
            if not variable:
                raise ValueError(f"Variable '{old_name}' not found in function '{function_name}'")
                
            variable.name = new_name
            return {"status": f"Successfully renamed variable '{old_name}' to '{new_name}' in function '{function_name}'"}
        except Exception as e:
            raise ValueError(f"Failed to rename variable: {str(e)}")

    def rename_variables(self, function_identifier: str | int, renames: List[Dict[str, str]] | Dict[str, str]) -> Dict[str, Any]:
        """Rename multiple local variables in a function.

        Args:
            function_identifier: Function name or address
            renames: Either a list of {"old": str, "new": str} pairs or a dict mapping old->new

        Returns:
            Dictionary with overall status and per-item results.

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or inputs are invalid
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        # Resolve function first
        func = self.binary_ops.get_function_by_name_or_address(function_identifier)
        if not func:
            raise ValueError(f"Function '{function_identifier}' not found")

        # Normalize renames into ordered list of {old, new}
        pairs: List[Dict[str, str]] = []
        if isinstance(renames, dict):
            for k, v in renames.items():
                if k is None or v is None:
                    continue
                pairs.append({"old": str(k), "new": str(v)})
        elif isinstance(renames, list):
            for entry in renames:
                try:
                    old = entry.get("old") or entry.get("from") or entry.get("src") or entry.get("before")
                    new = entry.get("new") or entry.get("to") or entry.get("dst") or entry.get("after")
                except Exception:
                    old = None
                    new = None
                if old is None or new is None:
                    continue
                pairs.append({"old": str(old), "new": str(new)})
        else:
            raise ValueError("Invalid 'renames' format; expected list of {old,new} or mapping old->new")

        if not pairs:
            raise ValueError("No valid rename pairs provided")

        results: List[Dict[str, Any]] = []
        success_count = 0

        # Apply in order; later entries can refer to names produced by earlier renames
        for idx, item in enumerate(pairs, start=1):
            old_name = item.get("old")
            new_name = item.get("new")
            if not old_name or not new_name:
                results.append({
                    "index": idx,
                    "old": old_name,
                    "new": new_name,
                    "success": False,
                    "error": "Missing old or new name",
                })
                continue

            try:
                var = None
                try:
                    if hasattr(func, "get_variable_by_name"):
                        var = func.get_variable_by_name(old_name)
                except Exception:
                    var = None
                if not var:
                    results.append({
                        "index": idx,
                        "old": old_name,
                        "new": new_name,
                        "success": False,
                        "error": f"Variable '{old_name}' not found",
                    })
                    continue

                # Primary method: direct property set
                try:
                    var.name = new_name
                except Exception:
                    # Fallback: attempt create_user_var with same storage/type but new name
                    try:
                        if hasattr(func, "create_user_var") and hasattr(var, "storage"):
                            vtype = getattr(var, "type", None)
                            if vtype is None:
                                # attempt to infer type if possible
                                vtype = getattr(bn, "Type", None)
                            func.create_user_var(var, vtype, new_name)
                        else:
                            raise
                    except Exception as e:
                        results.append({
                            "index": idx,
                            "old": old_name,
                            "new": new_name,
                            "success": False,
                            "error": f"Failed to rename: {e}",
                        })
                        continue

                success_count += 1
                results.append({
                    "index": idx,
                    "old": old_name,
                    "new": new_name,
                    "success": True,
                })
            except Exception as e:
                results.append({
                    "index": idx,
                    "old": old_name,
                    "new": new_name,
                    "success": False,
                    "error": str(e),
                })

        # Best-effort reanalysis for consistency
        try:
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
        except Exception:
            pass

        return {
            "status": "ok",
            "function": func.name,
            "address": hex(func.start),
            "total": len(pairs),
            "renamed": success_count,
            "results": results,
        }

    def retype_variable(self, function_name: str, name: str, type_str: str) -> Dict[str, str]:
        """Retype a variable inside a function
        
        Args:
            function_name: Name of the function containing the variable
            name: Current name of the variable
            type: C type for the variable
            
        Returns:
            Dictionary with status message
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or variable cannot be retyped
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
            
        # Find the function by name
        function = self.binary_ops.get_function_by_name_or_address(function_name)
        if not function:
            raise ValueError(f"Function '{function_name}' not found")
            
        # Try to rename the variable
        try:
            # Get the variable by name and rename it
            variable = function.get_variable_by_name(name)
            if not variable:
                raise ValueError(f"Variable '{name}' not found in function '{function_name}'")
                
            variable.type = type_str
            return {"status": f"Successfully retyped variable '{name}' to '{type_str}' in function '{function_name}'"}
        except Exception as e:
            raise ValueError(f"Failed to rename variable: {str(e)}")


    

    def set_function_prototype(self, function_address: str | int, prototype: str) -> Dict[str, str]:
        """Set a function's prototype by address.

        Args:
            function_address: Function address (hex string like 0x401000 or integer)
            prototype: C-style function prototype/type string (e.g., "int __cdecl f(int a)", or "int(int)" )

        Returns:
            Dictionary with status message.

        Raises:
            RuntimeError: If no binary is loaded.
            ValueError: If the function or prototype is invalid.
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        # Resolve function by name or address; do not auto-create if missing
        func = self.binary_ops.get_function_by_name_or_address(function_address)
        if not func:
            raise ValueError(f"Function not found for identifier '{function_address}'")

        # Normalize prototype (strip stray trailing semicolon)
        proto = (prototype or "").strip()
        if proto.endswith(";"):
            proto = proto[:-1].strip()

        # Best-effort parsing with fallbacks
        t = None
        last_error = None
        try:
            t, _ = self.binary_ops.current_view.parse_type_string(proto)
        except Exception as e:
            last_error = e
            t = None

        # Fallback 1: parse a declaration block and grab any function type
        if t is None:
            try:
                pr = self.binary_ops.current_view.parse_types_from_string(proto)
                if pr and getattr(pr, "types", None):
                    # Prefer an entry matching the current function name
                    chosen = None
                    if func.name in pr.types:
                        chosen = pr.types[func.name]
                    else:
                        # Otherwise pick the first type that looks like a function
                        for name, tobj in pr.types.items():
                            try:
                                if hasattr(tobj, "type_class") and int(getattr(bn.enums, "TypeClass", object).FunctionTypeClass) == int(getattr(tobj, "type_class")):
                                    chosen = tobj
                                    break
                            except Exception:
                                # Fallback: accept the first one
                                chosen = tobj
                                break
                    if chosen is not None:
                        t = chosen
            except Exception as e:
                last_error = e

        # Fallback 2: if the prototype looks like a bare "ret(args)" without a name,
        # synthesize a declaration by inserting the function's name.
        if t is None:
            import re as _re
            m = _re.match(r"^\s*([^()]+?)\s*\((.*)\)\s*$", proto)
            if m and func and func.name and func.name not in proto:
                ret = m.group(1).strip()
                args = m.group(2).strip()
                candidate = f"{ret} {func.name}({args})"
                try:
                    t, _ = self.binary_ops.current_view.parse_type_string(candidate)
                except Exception as e:
                    last_error = e

        if t is None:
            raise ValueError(f"Failed to parse prototype: {proto} ({last_error})")

        # Apply and reanalyze
        try:
            func.type = t
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
        except Exception as e:
            raise ValueError(f"Failed applying type: {str(e)}")

        return {
            "status": "ok",
            "function": func.name,
            "address": hex(func.start),
            "applied_type": str(t),
        }

    def declare_c_type(self, c_declaration: str) -> Dict[str, Any]:
        """Create or update a local type from a single C declaration.

        Accepts any C type declaration (struct/union/enum/typedef/function type) and defines
        the resulting named types in the current BinaryView's user types. If multiple types
        are declared, all are applied.

        Args:
            c_declaration: C declaration string (e.g., "typedef struct { int a; } Foo;")

        Returns:
            Dictionary with keys:
              - defined_types: map of type name -> declaration string
              - count: number of types defined/updated

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If parsing fails or no types are found
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        decl = (c_declaration or "").strip()
        if not decl:
            raise ValueError("Empty C declaration")

        try:
            result = self.binary_ops.current_view.parse_types_from_string(decl)
        except Exception as e:
            raise ValueError(f"Failed to parse declaration: {str(e)}")

        if not result or not getattr(result, "types", {}):
            raise ValueError("No named types found in declaration")

        defined: Dict[str, str] = {}
        for name, type_obj in result.types.items():
            try:
                self.binary_ops.current_view.define_user_type(name, type_obj)
                defined[str(name)] = str(type_obj)
            except Exception as e:
                raise ValueError(f"Failed to define type '{name}': {str(e)}")

        return {"defined_types": defined, "count": len(defined)}

    def set_local_variable_type(self, function_address: str | int, variable_name: str, new_type: str) -> Dict[str, str]:
        """Set a local variable's type in a function.

        Args:
            function_address: Function identifier (address in hex or int, or name)
            variable_name: Local variable name to retype
            new_type: C type string (e.g., "int *", "const char*", "struct Foo*")

        Returns:
            Dictionary with status message.

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If function/variable/type are invalid
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        func = self.binary_ops.get_function_by_name_or_address(function_address)
        if not func:
            raise ValueError(f"Function '{function_address}' not found")

        if not variable_name:
            raise ValueError("Missing variable name")

        # Resolve the variable by name
        var = None
        try:
            if hasattr(func, "get_variable_by_name"):
                var = func.get_variable_by_name(variable_name)
        except Exception:
            var = None

        if not var:
            raise ValueError(f"Variable '{variable_name}' not found in function '{func.name}'")

        # Parse type string
        try:
            t, _ = self.binary_ops.current_view.parse_type_string((new_type or "").strip())
        except Exception:
            t = None
        if t is None:
            # Fall back to assigning the string if BN API supports it; otherwise fail
            try:
                var.type = new_type
                applied = str(new_type)
            except Exception:
                raise ValueError(f"Failed to parse type: '{new_type}'")
        else:
            # Apply via variable object or function API
            applied = str(t)
            try:
                var.type = t
            except Exception:
                # Try create_user_var if direct assignment fails
                try:
                    if hasattr(func, "create_user_var") and hasattr(var, "storage"):
                        func.create_user_var(var, t, variable_name)
                    else:
                        raise ValueError("Retyping not supported by this Binary Ninja API version")
                except Exception as e:
                    raise ValueError(f"Failed to set variable type: {str(e)}")

        # Trigger reanalysis for consistency
        try:
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
        except Exception:
            pass

        return {
            "status": "ok",
            "function": func.name,
            "address": hex(func.start),
            "variable": variable_name,
            "applied_type": applied,
        }

    def patch_bytes(self, address: str | int, data: str | bytes | List[int], save_to_file: bool = True) -> Dict[str, Any]:
        """Patch bytes at a given address in the binary.
        
        Args:
            address: Address to patch (hex string like "0x401000" or integer)
            data: Bytes to write. Can be:
                - Hex string: "90 90" or "9090" or "0x90 0x90"
                - List of integers: [0x90, 0x90]
                - Bytes object: b"\x90\x90"
            save_to_file: If True (default), save the patched binary to disk and re-sign on macOS.
                If False, only modify the BinaryView in memory without affecting the original file.
                
        Returns:
            Dictionary with status, address, original bytes, and patched bytes
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If address or data format is invalid
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
        
        try:
            return self.binary_ops.patch_bytes(address, data, save_to_file)
        except Exception as e:
            bn.log_error(f"Error patching bytes: {e}")
            raise ValueError(f"Failed to patch bytes: {str(e)}")

    # -------- generic verb routing (expert_ops) --------
    def route_for(self, method: str, path: str):
        """Return a handler callable(params) -> (envelope, http_status) for a routed path, else None.

        GET serves ROUTES_GET; POST serves ROUTES_POST (every GET path plus the POST-only
        verbs). Any other method (DELETE included) is never routed here.
        """
        m = str(method or "").strip().upper()
        p = str(path or "")
        if m == "GET":
            verb = ROUTES_GET.get(p)
        elif m == "POST":
            verb = ROUTES_POST.get(p)
        else:
            return None
        if not verb:
            return None
        return functools.partial(self._run_verb, verb)

    def _run_verb(self, name: str, params: Optional[Dict[str, Any]]):
        """Run one expert verb in the request's scope -> (envelope, http_status).

        * expert_ops is imported lazily; an import failure answers 501 UNSUPPORTED_API.
        * bv is the request-scoped view (BinaryOperations.current_view honours the scope the
          HTTP dispatcher entered). A verb that needs a view gets 404 NOT_FOUND (with `available`)
          when none is in scope; viewless verbs = expert_ops.VIEWLESS.
        * close_binary closes only the view named by an explicit `binary` (never the global
          selection); the verb itself delegates to BinaryOperations.close_owned_view.
        * AmbiguousError -> 409 with candidates; ApiError -> its own status; any other
          exception -> logged traceback + 500 INTERNAL. The verb's own outcome is authoritative:
          a stale ambiguity note from an internal lookup never rewrites a non-ambiguity error.
          The ambiguity note is recorded only inside a request scope (rc.scope restores it on
          exit); outside one (SCOPE_EXEMPT paths) it is cleared, because a note left on the
          serving thread (BN_MCP_THREADED=0) would rewrite a LATER request's error into a stale
          409. The error envelope itself already carries error_code AMBIGUOUS and candidates.
        """
        verb = str(name or "")
        p = dict(params) if isinstance(params, dict) else {}
        ex = None
        ex_err = None
        try:
            from ..core import expert_ops as ex
        except Exception as e:  # ImportError or an error raised while importing the module
            ex = None
            ex_err = e
        if ex is None:
            return self._unsupported(verb, "expert_ops", ex_err)
        fn = getattr(ex, "VERB_FUNCS", {}).get(verb)
        make_env = getattr(ex, "make_envelope", None) or _plain_envelope
        err_env = getattr(ex, "error_envelope", None) or _plain_error_envelope
        viewless = set(getattr(ex, "VIEWLESS", ()) or ())
        if not callable(fn):
            return self._unsupported(verb, "the verb table", None)

        def _error(e, status):
            try:
                env = err_env(verb, e)
            except Exception:
                env = _plain_error_envelope(verb, e)
            if not isinstance(env, dict):
                env = _plain_error_envelope(verb, e)
            # Keep the structured extras an error carries (retry_after_s of a BUSY answer,
            # sha256_source, ...) that the compact envelope does not copy.
            try:
                pl = e.payload() if callable(getattr(e, "payload", None)) else None
                if isinstance(pl, dict):
                    for k, v in pl.items():
                        if k not in env:
                            env[k] = v
            except Exception:
                pass
            env["ok"] = False
            return env, status

        try:
            ops = self.binary_ops
            if verb in viewless:
                # Viewless verbs never read a view (their paths are scope-exempt, so no view
                # lock is held): hand them none rather than the unlocked global selection.
                bv = None
            else:
                bv = ops.current_view if ops is not None else None
            if verb not in viewless and bv is None:
                try:
                    avail = ops.available_binaries() if ops is not None else []
                except Exception:
                    avail = []
                raise rc.ApiError(
                    "NOT_FOUND",
                    "NOT_FOUND: no binary is selected for this verb; pass binary=<a selector from list_binaries> "
                    "(available lists the open binaries), or open and select a binary",
                    404,
                    {"available": avail},
                )
            if verb in _EXPLICIT_BINARY_VERBS:
                info = rc.info()
                if not (isinstance(info, dict) and info.get("resolved_by") == "explicit"):
                    raise rc.ApiError(
                        "BAD_ARGUMENT",
                        "%s requires an explicit binary=<selector>; it never acts on the implicit "
                        "global selection" % verb,
                        400,
                    )
            out = fn(ops, bv, p)
            env = make_env(verb, out)
            if not isinstance(env, dict):
                env = _plain_envelope(verb, out)
            rc.note_ambiguity(None)
            return env, 200
        except rc.AmbiguousError as e:
            # Out of scope (UNSET) -> clear, never leave a note that outlives this request.
            rc.note_ambiguity(e if rc.override_view() is not rc.UNSET else None)
            return _error(e, 409)
        except rc.ApiError as e:
            rc.note_ambiguity(None)
            try:
                status = int(e.http_status)
            except (TypeError, ValueError):
                status = 500
            if status < 400 or status > 599:
                status = 500
            if getattr(e, "code", None) == "AMBIGUOUS":
                status = 409
            return _error(e, status)
        except Exception as e:
            rc.note_ambiguity(None)
            try:
                bn.log_error(f"MCP verb {verb} failed: {e}")
                bn.log_error(traceback.format_exc())
            except Exception:
                pass
            return {
                "ok": False,
                "verb": verb,
                "error": ("INTERNAL: %s: %s" % (type(e).__name__, e))[:2000],
                "error_code": "INTERNAL",
            }, 500

    @staticmethod
    def _unsupported(verb: str, what: str, err):
        detail = ""
        if err is not None:
            detail = (": %s: %s" % (type(err).__name__, err))[:300]
        return {
            "ok": False,
            "verb": verb,
            "error": "UNSUPPORTED_API: %s is not available in this server build (%s%s)" % (verb, what, detail),
            "error_code": "UNSUPPORTED_API",
        }, 501
