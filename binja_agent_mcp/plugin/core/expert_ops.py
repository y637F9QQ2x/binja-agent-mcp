# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Expert analysis verbs of binja-agent-mcp (contract binja-agent-mcp/1, capability expert_v1): the /x/* routes
behind the bn_* MCP tools. Added by binja-agent-mcp (not in upstream): an explicit tool contract that never guesses,
IL walking with analysis-state and skip-reason reporting, SSA def-use and backward slices, value sets, branch
dependence, CFG, dominators and reachability with removed edges, uninitialized reads, a call graph with bounded paths
and edge provenance, CodeView GUID/age, return-value checks, sinks not dominated by a check call, a deterministic
context pack, entity resolution, bytes with patch information, and exact integer arithmetic.

DESIGN RULES (binding for every verb in this module)
- Pure, read-only functions over ONE BinaryView that the HTTP layer resolved and scoped for the request
  (request_context.scope). Nothing here selects, saves, patches, renames or retypes anything. The two
  exceptions are load_binary and close_binary, which delegate to BinaryOperations (close: server-owned views only).
- Calling convention: verb(ops, bv, p) -> {'result', 'truncated', 'next_offset', 'warnings', 'limits'}; p maps
  parameter names to values (query strings, or JSON values from a POST body). Errors are raised as
  request_context errors (ApiError / AmbiguousError / NotFoundError); MCP_WIRE maps them to HTTP answers and
  wraps successes with make_envelope().
- Never guess: an ambiguous name or address is an AmbiguousError with candidates, a missing one is a
  NotFoundError, a bare decimal address is BAD_ARGUMENT (write 0x<hex> or 0n<decimal>).
- Analysis hygiene: IL is fetched per function (the *_if_available form when generate=0). This module
  never blocks on whole-view analysis and never writes Function.analysis_skipped. A missing IL is NO_IL (422)
  carrying the function's skip status: an IL that is None is NOT evidence that there is no code.
- IL walks use traverse() (BNIL is a tree); functions are always iterated in start-address order; every list has
  an explicit cap and reports truncated / next_offset; Python-heavy loops stop at a time budget (warning
  'time-budget') clamped to config.ServerConfig.scan_time_budget_s.
- No single result may exceed 2 MiB of JSON (REFUSED_SIZE, 413).
- Static results are LEADS (hints to verify), not proof: dominance, branch dependence, value sets and slices can
  miss behaviour; every verb that can miss behaviour lists its blind spots or caveats.
- Thread safety: no module-level mutable state (the scan-budget cache is a write-once constant); every verb
  runs under the view lock the HTTP layer took for the request.

BN PYTHON API SURFACE USED (read from the installed 6.0.10601 package, api 2ddf304b; test fakes must model the
members a test exercises; every other member is feature-detected)
  BinaryView: functions, get_function_at, get_functions_by_name, get_functions_containing, get_symbols_by_name,
    get_symbol_by_raw_name, get_symbol_at, get_code_refs(addr, max_items=), get_data_refs(addr, max_items=),
    get_callers, get_callees, read, get_modification(addr, length), is_valid_offset, get_sections_at,
    get_string_at, get_type_by_name, get_instruction_length, get_disassembly, file.filename,
    file.original_filename, start, end, entry_point, image_base, parent_view, arch, platform, view_type,
    sections, analysis_state, analysis_progress, debug_info.parsers, metadata
  Function: name, start, symbol.type, address_ranges, basic_blocks, call_sites, is_call_instruction,
    get_basic_block_at, get_llils_at, llil/mlil/hlil and their *_if_available forms, parameter_vars, vars,
    stack_layout, type, analysis_skipped (READ only), analysis_skip_reason, analysis_skip_override, too_large,
    needs_update, has_unresolved_indirect_branches
  IL functions: instructions, basic_blocks, ssa_form, non_ssa_form, __getitem__(instr_index), root (HLIL AST),
    get_ssa_var_definition, get_ssa_var_uses, get_ssa_memory_definition
  IL instructions: operation(.name), address, expr_index, instr_index, traverse, ssa_form, non_ssa_form,
    params, output, output_exprs, dest, src, prev, offset, condition, true, false, constant, vars_read,
    vars_written, get_possible_values(options), get_ssa_var_possible_values, get_ssa_var_version(_after),
    get_possible_reg_values(_after), branch_dependence, src_memory, intrinsic
  BasicBlock: start, end, index, iteration (instruction text), outgoing_edges (.target .type .back_edge),
    dominators, post_dominators, strict_*, immediate_*, dominance_frontier, post_dominance_frontier,
    dominator_tree_children, post_dominator_tree_children
"""

from __future__ import annotations

import ast
import collections
import functools
import hashlib
import json
import math
import os
import re
import struct
import time

try:  # the plugin always runs inside Binary Ninja; the guard only keeps the module importable by offline tooling
    import binaryninja as bn
except Exception:  # pragma: no cover
    bn = None

from . import request_context as rc
from . import config as _cfg


EXPERT_API_VERSION = 1
MAX_RESULT_BYTES = 2 * 1024 * 1024
BATCH_MAX_ITEMS = 25
_BATCH_OUTPUT_BUDGET = MAX_RESULT_BYTES - 64 * 1024

_IMPORT_SYM_TYPES = frozenset({
    'ImportAddressSymbol', 'ImportedFunctionSymbol', 'ImportedDataSymbol', 'ExternalSymbol',
})
_CALL_OP_RE = re.compile(r'^(?:MLIL|HLIL|LLIL)_(?:CALL|TAILCALL|SYSCALL)(?:_UNTYPED)?(?:_SSA)?$|^LLIL_CALL_STACK_ADJUST$')
_CONST_OPS = frozenset({
    'MLIL_CONST', 'MLIL_CONST_PTR', 'MLIL_CONST_DATA', 'MLIL_FLOAT_CONST', 'MLIL_IMPORT', 'MLIL_EXTERN_PTR',
    'HLIL_CONST', 'HLIL_CONST_PTR', 'HLIL_CONST_DATA', 'HLIL_FLOAT_CONST', 'HLIL_IMPORT', 'HLIL_EXTERN_PTR',
    'LLIL_CONST', 'LLIL_CONST_PTR', 'LLIL_FLOAT_CONST', 'LLIL_EXTERN_PTR',
})
_ADDR_CONST_OPS = frozenset({
    'MLIL_CONST', 'MLIL_CONST_PTR', 'MLIL_IMPORT', 'MLIL_EXTERN_PTR',
    'HLIL_CONST', 'HLIL_CONST_PTR', 'HLIL_IMPORT', 'HLIL_EXTERN_PTR',
    'LLIL_CONST', 'LLIL_CONST_PTR', 'LLIL_EXTERN_PTR',
})
_SSA_VAR_READ_OPS = frozenset({'MLIL_VAR_SSA', 'MLIL_VAR_SSA_FIELD', 'MLIL_VAR_ALIASED', 'MLIL_VAR_ALIASED_FIELD'})
_SSA_SET_OPS = frozenset({
    'MLIL_SET_VAR_SSA', 'MLIL_SET_VAR_SSA_FIELD', 'MLIL_SET_VAR_SPLIT_SSA', 'MLIL_SET_VAR_ALIASED',
    'MLIL_SET_VAR_ALIASED_FIELD',
})
_LOAD_SSA_OPS = frozenset({'MLIL_LOAD_SSA', 'MLIL_LOAD_STRUCT_SSA'})
_STORE_SSA_OPS = frozenset({'MLIL_STORE_SSA', 'MLIL_STORE_STRUCT_SSA'})
_INTRINSIC_OPS = frozenset({'MLIL_INTRINSIC', 'MLIL_INTRINSIC_SSA', 'MLIL_MEMORY_INTRINSIC_SSA'})
_COPY_OPS = frozenset({'MLIL_VAR_SSA', 'MLIL_VAR_SSA_FIELD', 'MLIL_ZX', 'MLIL_SX', 'MLIL_LOW_PART'})
_CMP_OPS = frozenset({
    'MLIL_CMP_E', 'MLIL_CMP_NE', 'MLIL_CMP_SLT', 'MLIL_CMP_ULT', 'MLIL_CMP_SLE', 'MLIL_CMP_ULE',
    'MLIL_CMP_SGE', 'MLIL_CMP_UGE', 'MLIL_CMP_SGT', 'MLIL_CMP_UGT', 'MLIL_TEST_BIT',
})
# Outlined builtins (BN BuiltinType) appear as calls to synthetic __builtin_* symbols; memory intrinsics
# (__memcpy_u*/__memfill_*) appear as MLIL intrinsic statements. The intrinsic NAMES are matched by pattern; which
# instructions lift to them is architecture-dependent (UNVERIFIED per arch; the scan reports what it finds).
_BUILTIN_SINKS = (
    '__builtin_memcpy', '__builtin_memset', '__builtin_strcpy', '__builtin_strncpy', '__builtin_wcscpy',
    '__builtin_wmemcpy',
)
_INTRINSIC_SINK_RE = re.compile(r'^(?:__memcpy_u\d+|__memfill_u?\d+|__memset_u\d+|__builtin_\w+)$')

# Sink presets for bn_sinks and bn_undominated_sinks (a data table of public API names).
SINK_PRESETS = {
    'file': (
        'CreateFileW', 'CreateFileA', 'CreateFile2', 'NtCreateFile', 'ZwCreateFile', 'NtOpenFile', 'ZwOpenFile',
        'MoveFileExW', 'MoveFileW', 'MoveFileWithProgressW', 'CopyFileW', 'CopyFileExW', 'CopyFile2',
        'DeleteFileW', 'RemoveDirectoryW', 'CreateDirectoryW', 'CreateDirectoryExW', 'ReplaceFileW',
        'CreateHardLinkW', 'CreateSymbolicLinkW', 'SetFileAttributesW', 'SetFileInformationByHandle',
        'NtSetInformationFile', 'ZwSetInformationFile', 'DeviceIoControl', 'NtFsControlFile',
        'NtDeviceIoControlFile', 'SHFileOperationW',
    ),
    'registry': (
        'RegSetValueExW', 'RegSetValueExA', 'RegSetKeyValueW', 'RegCreateKeyExW', 'RegCreateKeyExA',
        'RegCreateKeyW', 'RegOpenKeyExW', 'RegDeleteKeyW', 'RegDeleteKeyExW', 'RegDeleteValueW', 'RegDeleteTreeW',
        'RegLoadKeyW', 'RegLoadAppKeyW', 'RegSaveKeyW', 'RegSaveKeyExW', 'RegRestoreKeyW', 'RegRenameKey',
        'RegCopyTreeW', 'NtSetValueKey', 'ZwSetValueKey', 'NtCreateKey', 'ZwCreateKey', 'NtDeleteKey',
        'NtDeleteValueKey', 'NtLoadKey', 'NtSaveKey', 'NtRenameKey',
    ),
    'security': (
        'SetNamedSecurityInfoW', 'SetSecurityInfo', 'SetFileSecurityW', 'SetKernelObjectSecurity',
        'NtSetSecurityObject', 'SetEntriesInAclW', 'ConvertStringSecurityDescriptorToSecurityDescriptorW',
        'AddAccessAllowedAce', 'AddAccessAllowedAceEx', 'SetSecurityDescriptorDacl',
    ),
    'process': (
        'CreateProcessW', 'CreateProcessA', 'CreateProcessAsUserW', 'CreateProcessAsUserA',
        'CreateProcessWithTokenW', 'CreateProcessWithLogonW', 'CreateProcessInternalW', 'NtCreateUserProcess',
        'ShellExecuteW', 'ShellExecuteExW', 'WinExec', 'OpenProcess', 'OpenProcessToken', 'DuplicateTokenEx',
        'DuplicateHandle',
    ),
    'load': (
        'LoadLibraryW', 'LoadLibraryA', 'LoadLibraryExW', 'LoadLibraryExA', 'LdrLoadDll', 'GetProcAddress',
        'CoCreateInstance', 'CoCreateInstanceEx', 'CoGetClassObject',
    ),
    'object': (
        'CreateNamedPipeW', 'CreateMutexW', 'CreateEventW', 'CreateFileMappingW', 'OpenFileMappingW',
        'NtCreateSection', 'DefineDosDeviceW', 'NtCreateSymbolicLinkObject',
    ),
    'service': ('CreateServiceW', 'ChangeServiceConfigW', 'StartServiceW', 'OpenServiceW', 'ControlService'),
    'memory': (
        'memcpy', 'memmove', 'memset', 'memcpy_s', 'memmove_s', 'RtlCopyMemory', 'RtlMoveMemory', 'wcscpy',
        'wcscpy_s', 'wcsncpy', 'wcscat', 'wcscat_s', 'strcpy', 'strncpy', 'strcat', 'StringCchCopyW',
        'StringCbCopyW', 'lstrcpyW', 'lstrcpynW',
    ),
    'alloc': (
        'malloc', 'calloc', 'realloc', 'HeapAlloc', 'HeapReAlloc', 'LocalAlloc', 'GlobalAlloc', 'VirtualAlloc',
        'RtlAllocateHeap', 'CoTaskMemAlloc', 'MIDL_user_allocate', '??2@YAPEAX_K@Z',
    ),
    'free': (
        'free', 'HeapFree', 'LocalFree', 'GlobalFree', 'RtlFreeHeap', 'CoTaskMemFree', 'MIDL_user_free',
        '??3@YAXPEAX@Z', '??3@YAXPEAX_K@Z',
    ),
    'impersonation': (
        'RpcImpersonateClient', 'RpcRevertToSelf', 'RpcRevertToSelfEx', 'CoImpersonateClient', 'CoRevertToSelf',
        'ImpersonateNamedPipeClient', 'ImpersonateLoggedOnUser', 'ImpersonateSelf', 'SetThreadToken',
        'NtSetInformationThread', 'RevertToSelf',
    ),
    'identity': (
        'AccessCheck', 'AccessCheckByType', 'AccessCheckByTypeResultList', 'AccessCheckAndAuditAlarmW',
        'AuthzAccessCheck', 'CheckTokenMembership', 'PrivilegeCheck', 'RpcBindingInqAuthClientW',
        'RpcBindingInqAuthClientExW', 'RpcServerInqCallAttributesW', 'I_RpcBindingInqLocalClientPID',
        'RpcGetAuthorizationContextForClient', 'CoQueryClientBlanket',
    ),
}
_DEFAULT_UNDOMINATED_PRESETS = ('file', 'registry', 'security', 'process', 'load', 'object', 'service', 'alloc')
# Default check calls of bn_undominated_sinks: an impersonation, an access decision, an identity read or a
# capability check.
_DEFAULT_GATES = (
    'RpcImpersonateClient', 'CoImpersonateClient', 'ImpersonateNamedPipeClient', 'ImpersonateLoggedOnUser',
    'SetThreadToken', 'NtSetInformationThread', 'AccessCheck', 'AccessCheckByType', 'AccessCheckByTypeResultList',
    'AccessCheckAndAuditAlarmW', 'AuthzAccessCheck', 'CheckTokenMembership', 'PrivilegeCheck',
    'RpcServerInqCallAttributesW', 'RpcBindingInqAuthClientW', 'RpcBindingInqAuthClientExW',
    'RpcGetAuthorizationContextForClient', 'CoQueryClientBlanket', 'I_RpcBindingInqLocalClientPID',
)
# Success semantics of common APIs for bn_return_check (documented API contracts; a hint for the reader, verify on
# Microsoft Learn before relying on it).
_RETURN_SEMANTICS = {
    'RpcImpersonateClient': 'RPC_STATUS; RPC_S_OK (0) is success; on failure the thread keeps the SERVER identity',
    'CoImpersonateClient': 'HRESULT; S_OK (0) is success; on failure the thread keeps the SERVER identity',
    'ImpersonateNamedPipeClient': 'BOOL; nonzero is success; on failure the thread keeps the SERVER identity',
    'ImpersonateLoggedOnUser': 'BOOL; nonzero is success',
    'ImpersonateSelf': 'BOOL; nonzero is success',
    'SetThreadToken': 'BOOL; nonzero is success',
    'NtSetInformationThread': 'NTSTATUS; NT_SUCCESS(status) (>= 0) is success',
    'RevertToSelf': 'BOOL; nonzero is success',
    'RpcRevertToSelf': 'RPC_STATUS; RPC_S_OK (0) is success',
    'CoRevertToSelf': 'HRESULT; S_OK (0) is success',
    'AccessCheck': 'BOOL = the CALL succeeded; the access DECISION is the AccessStatus OUT parameter',
    'AccessCheckByType': 'BOOL = the CALL succeeded; the access DECISION is the AccessStatus OUT parameter',
    'AuthzAccessCheck': 'BOOL = the CALL succeeded; the DECISION is in the AUTHZ_ACCESS_REPLY arrays',
    'CheckTokenMembership': 'BOOL = the CALL succeeded; membership is the IsMember OUT parameter',
    'PrivilegeCheck': 'BOOL = the CALL succeeded; the result is the pfResult OUT parameter',
}
_DFQ_ALIASES = {
    'from_lookup_table': 'FromAddressesInLookupTableQueryOption',
    'lookup_table': 'FromAddressesInLookupTableQueryOption',
    'fromaddressesinlookuptablequeryoption': 'FromAddressesInLookupTableQueryOption',
    'allow_writable': 'AllowReadingWritableMemoryQueryOption',
    'writable': 'AllowReadingWritableMemoryQueryOption',
    'allowreadingwritablememoryqueryoption': 'AllowReadingWritableMemoryQueryOption',
}
_DOM_KINDS = (
    'dominators', 'post_dominators', 'strict_dominators', 'strict_post_dominators', 'immediate_dominator',
    'immediate_post_dominator', 'dominance_frontier', 'post_dominance_frontier', 'dominator_tree_children',
    'post_dominator_tree_children',
)
_POSTDOM_CAVEAT = (
    'Dominance is intra-procedural and computed on the static CFG. BN documents that a block whose outgoing edges '
    'can lead to different exit blocks has only itself as post-dominator, so with several exits (returns, '
    'noreturn calls, exception edges) post-dominance is weak. Validation that happens on several paths, or in a '
    'caller, is invisible here. Treat the answer as a hint, not as proof that a path is unchecked.'
)
_BRANCH_DEP_CAVEAT = (
    'branch_dependence lists the branch decisions that are mandatory on the static CFG to reach the instruction. '
    'A check performed on several alternative paths is not mandatory and is not listed; an unrelated mandatory '
    'branch is listed. A hint only, not a reason to discard a lead.'
)
_SLICE_BLIND_SPOTS = (
    'interprocedural: a param source is not followed into callers (use bn_callers, then bn_backward_slice per call site)',
    'call_return: a value returned by a call is not followed into the callee',
    'memory: only ONE store hop is followed, and only when the store address is syntactically identical to the load address; aliasing through other pointers, other functions or other threads is not modelled',
    'globals and heap objects written elsewhere are not tracked',
)
_IL_LEVELS = ('hlil', 'mlil', 'llil')
_SECTION_DISASM_MAX_LINES = 3000
_AUTO_NAME_RE = re.compile(r'^(?:sub|j_sub|data|byte|word|dword|qword|unk|off|loc)_([0-9a-fA-F]{1,16})$')

_SCAN_BUDGET_CACHE = []  # write-once constant (see design rules)


# ---------------------------------------------------------------------------------------------------------------
# errors, formatting and parameters
# ---------------------------------------------------------------------------------------------------------------

def _api(code, msg, status, extra=None):
    return rc.ApiError(code, msg, status, extra)


def _is_rc_error(e):
    """True for every request_context error class (subclass relations between them are not assumed)."""
    for nm in ('ApiError', 'AmbiguousError', 'NotFoundError', 'GoneError'):
        k = getattr(rc, nm, None)
        if isinstance(k, type) and isinstance(e, k):
            return True
    return False


def _bad(msg, extra=None):
    return rc.ApiError('BAD_ARGUMENT', msg, 400, extra)


def _hx(n):
    try:
        n = int(n)
    except Exception:
        return None
    return ('-0x%x' % -n) if n < 0 else ('0x%x' % n)


def _clip(s, n):
    s = '' if s is None else str(s)
    return s if len(s) <= n else s[:max(0, n - 3)] + '...'


def _scan_budget():
    if _SCAN_BUDGET_CACHE:
        return _SCAN_BUDGET_CACHE[0]
    v = 120.0
    try:
        ac = getattr(_cfg, 'active_config', None)
        if callable(ac):
            v = float(getattr(ac().server, 'scan_time_budget_s', 120.0) or 120.0)
        else:
            sc = getattr(_cfg, 'ServerConfig', None)
            if sc is not None:
                v = float(getattr(sc(), 'scan_time_budget_s', 120.0) or 120.0)
    except Exception:
        v = 120.0
    v = max(1.0, min(v, 3600.0))
    _SCAN_BUDGET_CACHE.append(v)
    return v


# Parameter key that batch() sets on the parameters of every item it runs: the batch's own absolute monotonic
# deadline (a float). deadline() takes the EARLIER of it and the verb's own budget, so an item never runs past the
# batch budget (the bridge sends time_budget_s with x/batch so the batch answers inside the client's tool timeout).
# It can only shorten a call (a value that is not a float is ignored), so a caller that sets it hurts only itself.
_ENCLOSING_DEADLINE_KEY = '_bnmcp_enclosing_deadline'


def deadline(p, default):
    """Absolute monotonic deadline: p['time_budget_s'] or the verb default, clamped to [1, scan_time_budget_s], and
    never later than the enclosing batch deadline (p[_ENCLOSING_DEADLINE_KEY], set by batch() only)."""
    budget = _scan_budget()
    v = p.get('time_budget_s') if isinstance(p, dict) else None
    if v is None or (isinstance(v, str) and not v.strip()):
        s = float(default)
    else:
        if isinstance(v, bool):
            raise _bad('time_budget_s must be a number of seconds')
        try:
            s = float(v)
        except Exception:
            raise _bad('time_budget_s must be a number of seconds')
    s = max(1.0, min(s, budget))
    dl = time.monotonic() + s
    cap = p.get(_ENCLOSING_DEADLINE_KEY) if isinstance(p, dict) else None
    if type(cap) is float and cap < dl:
        dl = cap
    return dl


class _Ctx(object):
    """Per-call scratch: parameters, verb-local warnings, limits and the time budget."""
    __slots__ = ('p', 'warnings', 'limits', 'dl')

    def __init__(self, p, default_budget):
        self.p = p
        self.warnings = []
        self.limits = {}
        self.dl = deadline(p, default_budget)

    def warn(self, msg):
        msg = _clip(msg, 300)
        if msg not in self.warnings and len(self.warnings) < 50:
            self.warnings.append(msg)

    def expired(self):
        return time.monotonic() > self.dl

    def out(self, result, truncated=False, next_offset=None):
        return {
            'result': result,
            'truncated': bool(truncated),
            'next_offset': next_offset,
            'warnings': list(self.warnings),
            'limits': dict(self.limits),
        }

    # parameter accessors -----------------------------------------------------------------------------------
    def s(self, key, default=''):
        v = self.p.get(key)
        if v is None:
            return default
        return v if isinstance(v, str) else str(v)

    def req(self, key):
        v = self.s(key, '').strip()
        if not v:
            raise _bad('missing required parameter: %s' % key)
        return v

    def b(self, key, default):
        v = self.p.get(key)
        if v is None:
            return default
        if isinstance(v, bool):
            return v
        if isinstance(v, int):
            return v != 0
        t = str(v).strip().lower()
        if t == '':
            return default
        if t in ('1', 'true', 'yes', 'on', 'y', 't'):
            return True
        if t in ('0', 'false', 'no', 'off', 'n', 'f'):
            return False
        raise _bad('parameter %s must be a boolean (1/0/true/false), got %r' % (key, _clip(v, 40)))

    def i(self, key, default, lo, hi, strict=False):
        """Integer parameter. Out-of-range values are clamped with a warning, or rejected when strict (indices,
        versions: clamping would silently change the meaning of the query)."""
        v = self.p.get(key)
        if v is None or (isinstance(v, str) and not v.strip()):
            n = default
        else:
            if isinstance(v, bool):
                raise _bad('parameter %s must be an integer' % key)
            if isinstance(v, int):
                n = v
            else:
                t = str(v).strip()
                try:
                    if re.fullmatch(r'-?0[xX][0-9a-fA-F]+', t):
                        n = int(t, 16)
                    elif re.fullmatch(r'-?[0-9]+', t):
                        n = int(t, 10)
                    else:
                        raise ValueError(t)
                except Exception:
                    raise _bad('parameter %s must be an integer, got %r' % (key, _clip(t, 40)))
        if n < lo or n > hi:
            if strict:
                raise _bad('parameter %s=%d is outside %d..%d' % (key, n, lo, hi))
            c = lo if n < lo else hi
            self.warn('clamped %s=%d to %d (allowed %d..%d)' % (key, n, c, lo, hi))
            n = c
        self.limits[key] = n
        return n


def _require_view(bv):
    if bv is None:
        raise _api('NOT_FOUND', 'NOT_FOUND: no binary is selected for this verb; pass binary=<a selector from '
                                'list_binaries>', 404)


def _op(ins):
    o = getattr(ins, 'operation', None)
    n = getattr(o, 'name', None)
    return n if isinstance(n, str) else str(o)


def _is_call(ins):
    return bool(_CALL_OP_RE.match(_op(ins)))


def _text(ins, n=300):
    try:
        return _clip(str(ins), n)
    except Exception:
        return '<unrenderable>'


def _addr_of(ins, default=None):
    try:
        a = getattr(ins, 'address', None)
        return int(a) if a is not None else default
    except Exception:
        return default


# ---------------------------------------------------------------------------------------------------------------
# names, symbols, functions, addresses
# ---------------------------------------------------------------------------------------------------------------

def _basename(bv):
    try:
        f = getattr(bv, 'file', None)
        fn = getattr(f, 'filename', None) or ''
        ofn = getattr(f, 'original_filename', None) or ''
        path = ofn if (str(fn).lower().endswith('.bndb') and ofn) else (fn or ofn)
        b = os.path.basename(str(path).replace('\\', '/'))
        return b or '?'
    except Exception:
        return '?'


def _module_matches(bv, mod):
    b = _basename(bv).lower()
    stem = b.rsplit('.', 1)[0] if '.' in b else b
    m = mod.strip().lower()
    return bool(m) and (m == b or m == stem)


def _norm_sym_name(s):
    """Canonical import/API name: module!, __imp_ / _imp_ prefixes, @IAT suffix, j_ thunk prefix, stdcall @N."""
    if not s:
        return ''
    t = str(s).strip()
    if '!' in t:
        t = t.split('!', 1)[1]
    for pre in ('__imp__', '__imp_', '_imp__', '_imp_'):
        if t.startswith(pre):
            t = t[len(pre):]
            break
    if t.endswith('@IAT'):
        t = t[:-4]
    if t.startswith('j_'):
        t = t[2:]
    t = re.sub(r'@\d+$', '', t)
    return t


def _name_variants(s):
    t = _norm_sym_name(s)
    out = {t}
    if t.startswith('_') and len(t) > 1:
        out.add(t[1:])
    return out


def _sym_type_name(sym):
    try:
        t = getattr(sym, 'type', None)
        n = getattr(t, 'name', None)
        return n if isinstance(n, str) else (str(t) if t is not None else '')
    except Exception:
        return ''


def _func_sym_type(f):
    try:
        return _sym_type_name(f.symbol)
    except Exception:
        return ''


def _sym_at(bv, a):
    try:
        return bv.get_symbol_at(a)
    except Exception:
        return None


def _func_at(bv, a):
    try:
        return bv.get_function_at(a)
    except Exception:
        return None


def _fref(f):
    try:
        return {'name': f.name, 'start': _hx(f.start)}
    except Exception:
        return None


def _containing(bv, va):
    """All functions containing va, deduplicated by start, in start order."""
    try:
        fs = list(bv.get_functions_containing(va) or [])
    except Exception:
        fs = []
    uniq = {}
    for f in fs:
        try:
            uniq.setdefault(int(f.start), f)
        except Exception:
            continue
    return [uniq[k] for k in sorted(uniq)]


def _in_func(func, va):
    try:
        rs = list(func.address_ranges)
    except Exception:
        return None
    if not rs:
        return None
    for r in rs:
        try:
            if int(r.start) <= va < int(r.end):
                return True
        except Exception:
            continue
    return False


def sym(bv, va, func=None):
    """'<basename>!<func>+0x<off>' (always with an offset), else '<basename>!<symbol>', else '<basename>+0x<rva>'."""
    base = _basename(bv)
    try:
        va = int(va)
    except Exception:
        return '%s!?' % base
    try:
        f = func if (func is not None and _in_func(func, va)) else None
        if f is None:
            fs = _containing(bv, va)
            f = fs[0] if fs else None
        if f is not None:
            off = va - int(f.start)
            return '%s!%s%s' % (base, f.name, ('+0x%x' % off) if off >= 0 else ('-0x%x' % -off))
        s = _sym_at(bv, va)
        if s is not None and getattr(s, 'name', None):
            return '%s!%s' % (base, s.name)
    except Exception:
        pass
    try:
        return '%s+0x%x' % (base, va - int(bv.start))
    except Exception:
        return '%s@0x%x' % (base, va)


def _parse_num(s, what='address'):
    t = s.strip()
    if re.fullmatch(r'0[xX][0-9a-fA-F]+', t):
        return int(t[2:], 16)
    if re.fullmatch(r'0[nN][0-9]+', t):
        return int(t[2:], 10)
    if re.fullmatch(r'[0-9]+', t):
        raise _bad('bare digits are ambiguous for an %s: write 0x<hex> or 0n<decimal> (got %r)' % (what, t))
    if re.fullmatch(r'0[xXnN].*', t) and not re.search(r'[^0-9A-Za-z_]', t):
        raise _bad('malformed number %r: write 0x<hex> or 0n<decimal>' % t)
    return None


def _symbol_addrs(bv, name):
    """[(address, display name, symbol type)] for an exact symbol / function name, unique by address."""
    found = {}
    try:
        for s in (bv.get_symbols_by_name(name) or []):
            try:
                found.setdefault(int(s.address), (getattr(s, 'full_name', None) or s.name, _sym_type_name(s)))
            except Exception:
                continue
    except Exception:
        pass
    try:
        s = bv.get_symbol_by_raw_name(name)
        if s is not None:
            found.setdefault(int(s.address), (getattr(s, 'full_name', None) or s.name, _sym_type_name(s)))
    except Exception:
        pass
    try:
        for f in (bv.get_functions_by_name(name) or []):
            found.setdefault(int(f.start), (f.name, 'Function'))
    except Exception:
        pass
    return [(a, found[a][0], found[a][1]) for a in sorted(found)]


def _cands(rows):
    return [{'name': _clip(n, 160), 'start': _hx(a), 'kind': k} for (a, n, k) in rows][:50]


def _split_name_off(t):
    m = re.match(r'^(.+?)\+(0[xXnN][0-9a-fA-F]+)$', t)
    if not m:
        return t, 0
    off = _parse_num(m.group(2), 'offset')
    if off is None:
        raise _bad('malformed offset in %r' % t)
    return m.group(1), off


def parse_va(bv, s):
    """Address grammar: 0x<hex> | 0n<decimal> | symbol | symbol+0x<off> | <basename>!symbol[+0x<off>].

    Bare digits are BAD_ARGUMENT; a name naming more than one address is AmbiguousError; an unknown name is
    NotFoundError. A JSON integer is accepted as-is (it is not a string, so it is not ambiguous)."""
    if isinstance(s, bool):
        raise _bad('an address must be 0x<hex>, 0n<decimal> or a symbol')
    if isinstance(s, int):
        if s < 0:
            raise _bad('negative address')
        return s
    t = str(s if s is not None else '').strip()
    if not t:
        raise _bad('empty address')
    n = _parse_num(t)
    if n is not None:
        return n
    name, off = _split_name_off(t)
    candidates = [name]
    if '!' in name:
        mod, rest = name.split('!', 1)
        if _module_matches(bv, mod) and rest:
            candidates = [rest]
    rows = []
    for nm in candidates:
        rows = _symbol_addrs(bv, nm)
        if rows:
            break
    if not rows:
        m = _AUTO_NAME_RE.match(candidates[0])
        if m:
            return int(m.group(1), 16) + off
        hint = None
        if '!' in name and not _module_matches(bv, name.split('!', 1)[0]):
            hint = ['module prefix %r does not name this binary (%s)' % (name.split('!', 1)[0], _basename(bv))]
        raise rc.NotFoundError('symbol', t, hint)
    if len(rows) > 1:
        raise rc.AmbiguousError('symbol', t, _cands(rows))
    return rows[0][0] + off


def resolve_function_strict(bv, ident):
    """Exact function resolution (never guesses). An address must be an exact function start; a name is the union of
    get_functions_by_name and an exact display-name scan; more than one -> AmbiguousError; none -> NotFoundError
    (with case-insensitive hints, never a case-insensitive match)."""
    if isinstance(ident, bool) or ident is None:
        raise _bad('missing function')
    if isinstance(ident, int):
        addr = ident
        t = _hx(ident)
    else:
        t = str(ident).strip()
        if not t:
            raise _bad('missing function')
        addr = _parse_num(t, 'address')
    if addr is not None:
        f = _func_at(bv, addr)
        if f is None:
            hints = ['inside %s@%s (not its start)' % (g.name, _hx(g.start)) for g in _containing(bv, addr)][:10]
            raise rc.NotFoundError('function starting at', t, hints or None)
        return f
    name, off = _split_name_off(t)
    if off:
        raise _bad('%r is not a function start (offset +%s); use the function name or its start address'
                   % (t, _hx(off)))
    names = [name]
    if '!' in name:
        mod, rest = name.split('!', 1)
        if rest and _module_matches(bv, mod):
            names = [rest]
    matches = {}
    for nm in names:
        try:
            for f in (bv.get_functions_by_name(nm) or []):
                if f.name == nm or getattr(getattr(f, 'symbol', None), 'raw_name', None) == nm:
                    matches[(int(f.start), str(getattr(f, 'arch', '')))] = f
        except Exception:
            pass
        try:
            for f in bv.functions:
                if f.name == nm:
                    matches[(int(f.start), str(getattr(f, 'arch', '')))] = f
        except Exception:
            pass
        if matches:
            break
    if not matches:
        m = _AUTO_NAME_RE.match(names[0])
        if m and names[0].startswith(('sub_', 'j_sub_')):
            f = _func_at(bv, int(m.group(1), 16))
            if f is not None:
                return f
        hints = []
        try:
            low = names[0].lower()
            for f in bv.functions:
                if f.name.lower() == low:
                    hints.append('%s@%s (case differs)' % (f.name, _hx(f.start)))
                    if len(hints) >= 10:
                        break
        except Exception:
            pass
        raise rc.NotFoundError('function', t, hints or None)
    if len(matches) > 1:
        ordered = [matches[k] for k in sorted(matches)]
        raise rc.AmbiguousError('function', t, [{'name': f.name, 'start': _hx(f.start)} for f in ordered][:50])
    return list(matches.values())[0]


def _func_for_va(bv, va, function_param):
    fp = (function_param or '').strip() if isinstance(function_param, str) else function_param
    if fp:
        f = resolve_function_strict(bv, fp)
        inside = _in_func(f, va)
        if inside is False:
            raise _bad('%s is not inside %s@%s' % (_hx(va), f.name, _hx(f.start)))
        return f
    fs = _containing(bv, va)
    if not fs:
        raise rc.NotFoundError('function containing', _hx(va), None)
    if len(fs) > 1:
        raise rc.AmbiguousError('function containing', _hx(va),
                                [{'name': f.name, 'start': _hx(f.start)} for f in fs][:50])
    return fs[0]


def state_name(x):
    """AnalysisState(x).name, else str(x) (analysis states are always reported by NAME, e.g. 'IdleState')."""
    if x is None:
        return 'unknown'
    n = getattr(x, 'name', None)
    if isinstance(n, str) and n:
        return n
    try:
        from binaryninja.enums import AnalysisState
        return AnalysisState(int(x)).name
    except Exception:
        return str(x)


def _view_state(ops, bv):
    try:
        f = getattr(ops, 'analysis_summary', None)
        if callable(f):
            s = f(bv)
            if isinstance(s, dict) and s.get('state'):
                return str(s.get('state'))
    except Exception:
        pass
    try:
        return state_name(bv.analysis_state)
    except Exception:
        return 'unknown'


def skip_status(func):
    """Why a function may have no IL; every member is feature-detected and read-only."""
    out = {}
    for key, attr in (('skipped', 'analysis_skipped'), ('too_large', 'too_large'), ('needs_update', 'needs_update')):
        try:
            v = getattr(func, attr)
            out[key] = bool(v) if v is not None else None
        except Exception:
            out[key] = None
    for key, attr in (('skip_reason', 'analysis_skip_reason'), ('skip_override', 'analysis_skip_override')):
        try:
            v = getattr(func, attr)
            out[key] = state_name(v) if v is not None else None
        except Exception:
            out[key] = None
    return out


def _norm_level(level):
    t = str(level or 'hlil').strip().lower()
    aliases = {'il': 'llil', 'low': 'llil', 'medium': 'mlil', 'high': 'hlil'}
    t = aliases.get(t, t)
    if t not in _IL_LEVELS:
        raise _bad('il must be one of hlil, mlil, llil (got %r)' % _clip(level, 30))
    return t


def il_of(func, level, ssa=False, generate=True):
    """IL of one function. generate=False uses the *_if_available form (nothing is generated). None -> NO_IL (422)
    with the skip status. Never writes analysis_skipped, never blocks on whole-view analysis."""
    lvl = _norm_level(level)
    il = None
    try:
        if generate:
            il = getattr(func, lvl)
        else:
            av = lvl + '_if_available'
            il = getattr(func, av) if hasattr(func, av) else getattr(func, lvl)
    except Exception:
        il = None
    if il is not None and ssa:
        try:
            il = il.ssa_form
        except Exception:
            il = None
    if il is None:
        st = skip_status(func)
        why = ('IL not generated yet (generate=0 reads only already-available IL; pass generate=1)'
               if not generate else 'IL unavailable for this function')
        raise _api('NO_IL', '%s%s for %s@%s: %s. A missing IL is NOT evidence that there is no code; see '
                   'function_status.skip_reason' % (lvl, '-ssa' if ssa else '', getattr(func, 'name', '?'),
                                                    _hx(getattr(func, 'start', 0)), why), 422,
                   {'function_status': st, 'function': _fref(func), 'il': lvl, 'ssa': bool(ssa),
                    'generate': bool(generate)})
    return il


def _il_get(il, idx):
    try:
        return il[idx]
    except Exception:
        return None


# ---------------------------------------------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------------------------------------------

def _dtl_lines(lines_iter, default_addr):
    out = []
    last = default_addr
    for ln in lines_iter:
        a = getattr(ln, 'address', None)
        try:
            a = int(a) if a is not None else last
        except Exception:
            a = last
        last = a
        out.append((a, str(ln)))
    return out


def _instr_lines(ilf, default_addr):
    out = []
    last = default_addr
    for ins in ilf.instructions:
        a = _addr_of(ins, None)
        if a is None:
            a = last
        last = a
        out.append((a, _text(ins, 100000)))
    return out


def _asm_lines(bv, func):
    out = []
    try:
        blocks = sorted(func.basic_blocks, key=lambda b: int(b.start))
    except Exception:
        blocks = []
    for blk in blocks:
        start = int(blk.start)
        end = int(blk.end)
        done = False
        mark = len(out)
        try:
            a = start
            for tokens, size in blk:
                out.append((a, ''.join(str(t) for t in tokens)))
                a += int(size)
                if size <= 0:
                    break
            done = True
        except Exception:
            del out[mark:]
            done = False
        if done:
            continue
        a = start
        while a < end and len(out) < 200000:
            try:
                n = int(bv.get_instruction_length(a))
            except Exception:
                n = 0
            if n <= 0:
                out.append((a, '?? (undecodable)'))
                break
            try:
                t = bv.get_disassembly(a)
            except Exception:
                t = None
            out.append((a, t if t else '??'))
            a += n
    return out


def render_function_lines(bv, func, il='hlil', ssa=False, render='ast', generate=True):
    """(lines [(addr, text)], render_used). render_used is one of 'ast-lines', 'ast-get_lines', 'non-ast', 'asm'.

    il='asm' renders the disassembly of each basic block in address order. HLIL with render='ast' renders the AST
    root (nested bodies, braces, indentation) via root.lines, then root.get_lines(); otherwise, and for MLIL/LLIL,
    the flat instruction loop is used (render_used 'non-ast')."""
    lvl = str(il or 'hlil').strip().lower()
    if lvl in ('asm', 'disasm', 'disassembly'):
        return _asm_lines(bv, func), 'asm'
    lvl = _norm_level(lvl)
    ilf = il_of(func, lvl, ssa, generate)
    start = getattr(func, 'start', 0)
    r = str(render or 'ast').strip().lower()
    if lvl == 'hlil' and r == 'ast':
        root = None
        try:
            root = ilf.root
        except Exception:
            root = None
        if root is not None:
            try:
                lines = _dtl_lines(root.lines, start)
                if lines:
                    return lines, 'ast-lines'
            except Exception:
                pass
            try:
                lines = _dtl_lines(root.get_lines(), start)
                if lines:
                    return lines, 'ast-get_lines'
            except Exception:
                pass
    return _instr_lines(ilf, start), 'non-ast'


def _fmt_line(a, t):
    try:
        return '%08x  %s' % (int(a), t)
    except Exception:
        return '????????  %s' % t


# ---------------------------------------------------------------------------------------------------------------
# IL location helpers
# ---------------------------------------------------------------------------------------------------------------

def mlil_at(func, va, ssa=False, generate=True):
    """MLIL (or MLIL-SSA) STATEMENTS at va: get_llils_at -> .mlils/.mlil -> (ssa_form) -> statement, deduplicated
    by expr_index, ordered by instruction index. Falls back to a scan of the IL statements whose address is va."""
    il = il_of(func, 'mlil', ssa, generate)
    found = {}
    try:
        llils = list(func.get_llils_at(va) or [])
    except Exception:
        llils = []
    for l in llils:
        ms = None
        try:
            ms = list(l.mlils or [])
        except Exception:
            ms = None
        if not ms:
            try:
                m = l.mlil
                ms = [m] if m is not None else []
            except Exception:
                ms = []
        for m in ms:
            try:
                e = m.ssa_form if ssa else m
                st = _il_get(il, e.instr_index)
                st = st if st is not None else e
                found[int(st.expr_index)] = st
            except Exception:
                continue
    if not found:
        try:
            for ins in il.instructions:
                if _addr_of(ins) == va:
                    found[int(ins.expr_index)] = ins
        except Exception:
            pass

    def _k(i):
        try:
            return (int(i.instr_index), int(i.expr_index))
        except Exception:
            return (0, 0)
    return sorted(found.values(), key=_k)


def mlil_ssa_at(func, va, generate=True):
    return mlil_at(func, va, True, generate)


# ---------------------------------------------------------------------------------------------------------------
# value sets, variables
# ---------------------------------------------------------------------------------------------------------------

def serialize_pvs(v):
    """PossibleValueSet / RegisterValue -> JSON. 'undetermined' is (type name == 'UndeterminedValue')."""
    if v is None:
        return {'type': 'None', 'undetermined': True}
    t = getattr(v, 'type', None)
    tn = getattr(t, 'name', None)
    if not isinstance(tn, str):
        tn = str(t)
    out = {'type': tn, 'undetermined': tn == 'UndeterminedValue'}
    try:
        out['repr'] = _clip(repr(v), 300)
    except Exception:
        pass
    for k in ('value', 'offset'):
        try:
            x = getattr(v, k)
            if isinstance(x, int) and not isinstance(x, bool):
                out[k] = _hx(x)
        except Exception:
            pass
    for k in ('size', 'count', 'confidence'):
        try:
            x = getattr(v, k)
            if isinstance(x, int) and not isinstance(x, bool):
                out[k] = x
        except Exception:
            pass
    try:
        r = getattr(v, 'reg')
        if r is not None:
            out['reg'] = str(r)
    except Exception:
        pass
    try:
        rs = list(getattr(v, 'ranges'))
        out['ranges'] = [{'start': _hx(x.start), 'end': _hx(x.end), 'step': int(x.step)} for x in rs[:64]]
        if len(rs) > 64:
            out['ranges_truncated'] = len(rs)
    except Exception:
        pass
    try:
        vs = sorted(int(x) for x in getattr(v, 'values'))
        out['values'] = [_hx(x) for x in vs[:256]]
        if len(vs) > 256:
            out['values_truncated'] = len(vs)
    except Exception:
        pass
    try:
        tb = list(getattr(v, 'table'))
        out['table'] = [{'from': [_hx(x) for x in list(e.from_values)[:16]], 'to': _hx(e.to_value)} for e in tb[:64]]
    except Exception:
        pass
    return out


def _vkey(var):
    try:
        return ('k', int(var.source_type), int(var.index), int(var.storage))
    except Exception:
        return ('n', str(getattr(var, 'name', var)))


def _svkey(sv):
    return (_vkey(getattr(sv, 'var', sv)), int(getattr(sv, 'version', -1)))


def _svname(sv):
    try:
        return '%s#%d' % (sv.var.name, int(sv.version))
    except Exception:
        return str(sv)


def _var_storage_kind(var):
    try:
        n = var.source_type.name
        return {'StackVariableSourceType': 'stack', 'RegisterVariableSourceType': 'register',
                'FlagVariableSourceType': 'flag'}.get(n, n)
    except Exception:
        return 'unknown'


def _param_keys(func):
    keys = {}
    try:
        for i, v in enumerate(func.parameter_vars):
            keys[_vkey(v)] = i
    except Exception:
        pass
    return keys


def _ssa_reads(expr):
    """[(node, ssa_var)] for every SSA variable read anywhere in expr (traverse)."""
    out = []
    try:
        for node in expr.traverse(lambda n: n if _op(n) in _SSA_VAR_READ_OPS else None):
            sv = getattr(node, 'src', None)
            if sv is not None and hasattr(sv, 'version'):
                out.append((node, sv))
    except Exception:
        pass
    return out


def _nodes(expr, opset):
    try:
        return list(expr.traverse(lambda n: n if _op(n) in opset else None))
    except Exception:
        return []


def _const_val(node):
    try:
        c = getattr(node, 'constant', None)
        if isinstance(c, int) and not isinstance(c, bool):
            return c
    except Exception:
        pass
    try:
        v = getattr(node, 'value', None)
        x = getattr(v, 'value', None)
        if isinstance(x, int) and not isinstance(x, bool):
            return x
    except Exception:
        pass
    return None


def _dest_addr(ins):
    d = getattr(ins, 'dest', None)
    if d is None or isinstance(d, list):
        return None
    if _op(d) in _ADDR_CONST_OPS:
        return _const_val(d)
    return None


def _name_at(bv, a, cache=None):
    if a is None:
        return None
    if cache is not None and a in cache:
        return cache[a]
    n = None
    f = _func_at(bv, a)
    if f is not None:
        n = f.name
    else:
        s = _sym_at(bv, a)
        if s is not None:
            n = getattr(s, 'name', None)
    if cache is not None:
        cache[a] = n
    return n


def _callee_name(bv, ins, cache=None):
    a = _dest_addr(ins)
    if a is None:
        return None, None
    return a, _name_at(bv, a, cache)


# ---------------------------------------------------------------------------------------------------------------
# call graph edges
# ---------------------------------------------------------------------------------------------------------------

def _is_call_insn(func, a):
    try:
        f = getattr(func, 'is_call_instruction', None)
        if callable(f):
            return bool(f(a))
    except Exception:
        pass
    return None


def _il_call_map(func):
    """{address: [call statement]} from already-available MLIL (nothing generated)."""
    m = {}
    try:
        il = getattr(func, 'mlil_if_available') if hasattr(func, 'mlil_if_available') else None
    except Exception:
        il = None
    if il is None:
        return m
    try:
        for ins in il.instructions:
            if _is_call(ins):
                a = _addr_of(ins)
                if a is not None:
                    m.setdefault(a, []).append(ins)
    except Exception:
        pass
    return m


def _edges(bv, func, cache):
    """Outgoing call edges of func, sorted by (site, target); cached per request in `cache`.

    prov: direct | tailcall (a call site that is not a call instruction) | import | unresolved-indirect."""
    key = ('edges', int(func.start))
    if key in cache:
        return cache[key]
    names = cache.setdefault('names', {})
    try:
        sites = sorted({int(r.address) for r in func.call_sites})
    except Exception:
        sites = sorted(_il_call_map(func).keys())
    il_calls = None
    out = []
    for s in sites:
        try:
            addrs = sorted({int(a) for a in (bv.get_callees(s, func) or [])})
        except Exception:
            addrs = []
        is_call = _is_call_insn(func, s)
        if not addrs:
            if il_calls is None:
                il_calls = _il_call_map(func)
            for ins in il_calls.get(s, []):
                a = _dest_addr(ins)
                if a is not None:
                    addrs.append(a)
            addrs = sorted(set(addrs))
        if not addrs:
            out.append({'site': s, 'to': None, 'to_name': None, 'prov': 'unresolved-indirect', 'func': None})
            continue
        for a in addrs:
            f2 = _func_at(bv, a)
            st = _sym_type_name(_sym_at(bv, a))
            imp = st in _IMPORT_SYM_TYPES or (f2 is not None and _func_sym_type(f2) in _IMPORT_SYM_TYPES)
            if imp:
                prov = 'import'
            elif is_call is False:
                prov = 'tailcall'
            else:
                prov = 'direct'
            nm = f2.name if f2 is not None else _name_at(bv, a, names)
            out.append({'site': s, 'to': a, 'to_name': nm, 'prov': prov, 'func': None if imp else f2})
    out.sort(key=lambda e: (e['site'], -1 if e['to'] is None else e['to']))
    cache[key] = out
    return out


def _callers_of(bv, func):
    """[(caller function, site, prov)] sorted by (caller start, site)."""
    refs = []
    try:
        refs = list(bv.get_callers(int(func.start)))
    except Exception:
        try:
            refs = list(bv.get_code_refs(int(func.start)))
        except Exception:
            refs = []
    seen = {}
    for r in refs:
        f = getattr(r, 'function', None)
        try:
            site = int(r.address)
        except Exception:
            continue
        if f is None:
            continue
        k = (int(f.start), site)
        if k in seen:
            continue
        ic = _is_call_insn(f, site)
        seen[k] = (f, site, 'tailcall' if ic is False else 'direct')
    return [seen[k] for k in sorted(seen)]


def _edge_json(bv, f, e):
    return {
        'from': f.name, 'from_start': _hx(f.start), 'site': _hx(e['site']), 'sym': sym(bv, e['site'], f),
        'to': e['to_name'], 'to_start': _hx(e['to']) if e['to'] is not None else None, 'prov': e['prov'],
    }


# ---------------------------------------------------------------------------------------------------------------
# misc helpers
# ---------------------------------------------------------------------------------------------------------------

def modified_bytes(bv, funcs, extra_ranges=()):
    """Count of non-Original bytes over the merged address ranges of funcs plus extra_ranges ((start, end) pairs,
    e.g. the data a pack renders; an entry None means an unknown extent) via get_modification; None if the API is
    unavailable or fails, or an extent is unknown (fail closed)."""
    if not hasattr(bv, 'get_modification'):
        return None
    ranges = []
    for r in extra_ranges or ():
        if r is None:
            return None
        try:
            a, b = int(r[0]), int(r[1])
        except Exception:
            return None
        if b > a:
            ranges.append((a, b))
    for f in funcs:
        try:
            rs = list(f.address_ranges)
        except Exception:
            return None
        for r in rs:
            try:
                ranges.append((int(r.start), int(r.end)))
            except Exception:
                return None
    ranges.sort()
    merged = []
    for a, b in ranges:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    total = 0
    try:
        for a, b in merged:
            pos = a
            while pos < b:
                n = min(65536, b - pos)
                for st in bv.get_modification(pos, n):
                    nm = getattr(st, 'name', None)
                    if nm is not None:
                        if nm != 'Original':
                            total += 1
                    elif int(st) != 0:
                        total += 1
                pos += n
    except Exception:
        return None
    return total


def _mod_summary(bv, va, length):
    if not hasattr(bv, 'get_modification') or length <= 0:
        return None
    try:
        counts = {}
        for st in bv.get_modification(va, length):
            nm = getattr(st, 'name', None) or ('Original' if int(st) == 0 else str(int(st)))
            counts[nm] = counts.get(nm, 0) + 1
        return {'counts': dict(sorted(counts.items())),
                'modified': sum(v for k, v in counts.items() if k != 'Original')}
    except Exception:
        return None


def _section_names(bv, va):
    try:
        return sorted({s.name for s in bv.get_sections_at(va)})
    except Exception:
        return []


def _info_for(ops, bv):
    info = None
    try:
        info = rc.info()
    except Exception:
        info = None
    if not isinstance(info, dict):
        try:
            f = getattr(ops, 'describe_view', None)
            info = f(bv, 'explicit') if callable(f) else None
        except Exception:
            info = None
    info = dict(info) if isinstance(info, dict) else {}
    if not info.get('sha256'):
        try:
            f = getattr(ops, 'view_sha256', None)
            if callable(f):
                h, src = f(bv)
                info['sha256'] = h
                info.setdefault('sha256_source', src)
        except Exception:
            pass
    if not info.get('binary_id'):
        try:
            f = getattr(ops, 'binary_id', None)
            if callable(f):
                info['binary_id'] = f(bv)
        except Exception:
            pass
    info.setdefault('basename', _basename(bv))
    return info


def _bn_version():
    try:
        return str(bn.core_version()) if bn is not None else ''
    except Exception:
        return ''


def _sorted_functions(bv):
    try:
        return sorted(bv.functions, key=lambda f: int(f.start))
    except Exception:
        return []


def _blocks_of(func, level, generate=True):
    """(il or None, [block info]) for level disasm|llil|mlil|mlil_ssa|hlil; blocks sorted by start."""
    lv = str(level or 'disasm').strip().lower()
    if lv in ('disasm', 'asm', 'native'):
        il = None
        try:
            raw = list(func.basic_blocks)
        except Exception:
            raw = []
    else:
        ssa = lv.endswith('_ssa')
        base = lv[:-4] if ssa else lv
        il = il_of(func, base, ssa, generate)
        try:
            raw = list(il.basic_blocks)
        except Exception:
            raw = []
    out = []
    for b in raw:
        try:
            st, en, ix = int(b.start), int(b.end), int(b.index)
        except Exception:
            continue
        if il is None:
            va = st
        else:
            va = _addr_of(_il_get(il, st), None)
        out.append({'bb': b, 'index': ix, 'start': st, 'end': en, 'va': va})
    out.sort(key=lambda d: (d['start'], d['index']))
    return il, out


def _block_json(d, il):
    j = {'index': d['index'], 'va': _hx(d['va']) if d['va'] is not None else None}
    if il is not None:
        j['instr_range'] = [d['start'], d['end']]
    else:
        j['end'] = _hx(d['end'])
    return j


def _find_block(func, il, blocks, ref):
    """A block by '#<index>' or by an address it contains (disasm) / an IL statement address (IL levels)."""
    r = str(ref or '').strip()
    if not r:
        raise _bad('missing block reference')
    if r.startswith('#'):
        try:
            ix = int(r[1:], 10)
        except Exception:
            raise _bad('malformed block index %r' % r)
        for d in blocks:
            if d['index'] == ix:
                return d
        raise rc.NotFoundError('block', r, ['#%d' % d['index'] for d in blocks][:50])
    va = _parse_num(r)
    if va is None:
        raise _bad('block reference must be #<index> or 0x<address> (got %r)' % r)
    hits = []
    if il is None:
        hits = [d for d in blocks if d['start'] <= va < d['end']]
    else:
        idxs = set()
        try:
            for ins in il.instructions:
                if _addr_of(ins) == va:
                    idxs.add(int(ins.instr_index))
        except Exception:
            pass
        hits = [d for d in blocks if any(d['start'] <= i < d['end'] for i in idxs)]
    if not hits:
        raise rc.NotFoundError('block containing', r, ['use #<index> from bn_cfg at this level'])
    if len(hits) > 1:
        raise rc.AmbiguousError('block containing', r,
                                [{'name': '#%d' % d['index'], 'start': _hx(d['va'])} for d in hits][:50])
    return hits[0]


# ---------------------------------------------------------------------------------------------------------------
# verbs: server / binary / function
# ---------------------------------------------------------------------------------------------------------------

def server_info(ops, bv, p):
    c = _Ctx(p, 5)
    nviews = None
    try:
        f = getattr(ops, 'open_view_count', None)
        nviews = int(f()) if callable(f) else None
    except Exception:
        nviews = None
    return c.out({
        'version': str(getattr(_cfg, 'SERVER_VERSION', '') or ''),
        'contract': str(getattr(_cfg, 'MCP_CONTRACT', '') or ''),
        'expert_api': EXPERT_API_VERSION,
        'verbs': sorted(VERB_FUNCS),
        'viewless': sorted(VIEWLESS),
        'mutating': sorted(_MUTATING_VERBS),
        'batch_max_items': BATCH_MAX_ITEMS,
        'max_result_bytes': MAX_RESULT_BYTES,
        'scan_time_budget_s': _scan_budget(),
        'il_levels': list(_IL_LEVELS) + ['asm'],
        'sink_presets': sorted(SINK_PRESETS),
        'dataflow_options': sorted(set(_DFQ_ALIASES.values())),
        'bn_core_version': _bn_version(),
        'open_views': nviews,
        'address_syntax': '0x<hex> | 0n<decimal> | symbol | symbol+0x<off> | <basename>!symbol[+0x<off>]; '
                          'bare digits are rejected',
    })


def binary_info(ops, bv, p):
    c = _Ctx(p, 10)
    info = _info_for(ops, bv)
    res = {'binary': {k: info.get(k) for k in ('view_id', 'binary_id', 'sha256', 'sha256_source', 'filename',
                                                'original_filename', 'basename') if k in info}}
    for k, fn in (('arch', lambda: bv.arch.name), ('platform', lambda: bv.platform.name),
                  ('view_type', lambda: bv.view_type)):
        try:
            res[k] = str(fn())
        except Exception:
            res[k] = None
    for k in ('start', 'end', 'entry_point', 'image_base'):
        try:
            res[k] = _hx(getattr(bv, k))
        except Exception:
            res[k] = None
    try:
        res['function_count'] = len(bv.functions)
    except Exception:
        try:
            res['function_count'] = sum(1 for _ in bv.functions)
        except Exception:
            res['function_count'] = None
    res['analysis_state'] = _view_state(ops, bv)
    try:
        res['analysis_progress'] = str(bv.analysis_progress)
    except Exception:
        res['analysis_progress'] = None
    secs = []
    try:
        for name, s in sorted(bv.sections.items(), key=lambda kv: int(kv[1].start)):
            secs.append({'name': name, 'start': _hx(s.start), 'end': _hx(s.end),
                         'semantics': state_name(getattr(s, 'semantics', None))})
    except Exception:
        pass
    res['sections'] = secs[:128]
    if len(secs) > 128:
        c.warn('sections truncated at 128 of %d' % len(secs))
    try:
        res['debug_parsers'] = sorted(set(bv.debug_info.parsers))
    except Exception:
        res['debug_parsers'] = None
    return c.out(res, truncated=len(secs) > 128)


def function_status(ops, bv, p):
    c = _Ctx(p, 10)
    f = resolve_function_strict(bv, c.req('function'))
    res = {'function': _fref(f), 'sym': sym(bv, f.start, f), 'status': skip_status(f)}
    avail = {}
    for lvl in _IL_LEVELS:
        try:
            avail[lvl] = getattr(f, lvl + '_if_available') is not None
        except Exception:
            avail[lvl] = None
    res['il_available'] = avail
    try:
        res['basic_block_count'] = len(f.basic_blocks)
    except Exception:
        res['basic_block_count'] = None
    try:
        res['has_unresolved_indirect_branches'] = bool(f.has_unresolved_indirect_branches)
    except Exception:
        res['has_unresolved_indirect_branches'] = None
    try:
        res['symbol_type'] = _func_sym_type(f)
    except Exception:
        res['symbol_type'] = None
    try:
        res['prototype'] = _clip(str(f.type), 400)
    except Exception:
        res['prototype'] = None
    res['analysis_state'] = _view_state(ops, bv)
    res['note'] = ('IL missing is NOT "no code": read status.skip_reason; generate=1 on bn_decompile builds the IL '
                   'of THIS function only (no whole-view wait, analysis_skipped is never changed)')
    return c.out(res)


def decompile(ops, bv, p):
    c = _Ctx(p, 60)
    f = resolve_function_strict(bv, c.req('function'))
    il = c.s('il', 'hlil').strip().lower() or 'hlil'
    if il not in ('hlil', 'mlil', 'llil', 'asm', 'disasm'):
        raise _bad('il must be one of hlil, mlil, llil, asm (got %r)' % _clip(il, 30))
    ssa = c.b('ssa', False)
    render = c.s('render', 'ast').strip().lower() or 'ast'
    if render not in ('ast', 'legacy', 'non-ast', 'flat'):
        raise _bad('render must be ast or legacy (got %r)' % _clip(render, 30))
    generate = c.b('generate', True)
    off = c.i('line_offset', 0, 0, 10 ** 9)
    max_lines = c.i('max_lines', 400, 1, 50000)
    max_chars = c.i('max_chars', 60000, 200, 1800000)
    lines, used = render_function_lines(bv, f, il, ssa, 'ast' if render == 'ast' else 'non-ast', generate)
    total = len(lines)
    picked = []
    size = 0
    i = off
    while i < total and len(picked) < max_lines:
        s = _fmt_line(lines[i][0], lines[i][1])
        if size + len(s) + 1 > max_chars:
            if not picked:
                picked.append(s[:max(0, max_chars - 40)] + ' [LINE CUT AT max_chars]')
                i += 1
            break
        picked.append(s)
        size += len(s) + 1
        i += 1
    nxt = i if i < total else None
    if off > total:
        c.warn('line_offset %d is past the end (%d lines)' % (off, total))
    return c.out({
        'function': _fref(f), 'sym': sym(bv, f.start, f), 'il': 'asm' if il in ('asm', 'disasm') else il,
        'ssa': bool(ssa) and il not in ('asm', 'disasm'), 'render_used': used, 'total_lines': total,
        'line_offset': off, 'returned_lines': len(picked), 'next_line_offset': nxt, 'text': '\n'.join(picked),
    }, truncated=nxt is not None, next_offset=nxt)


# ---------------------------------------------------------------------------------------------------------------
# verbs: IL search, SSA, slices, values
# ---------------------------------------------------------------------------------------------------------------

def _parse_il_level(s):
    t = str(s or 'mlil').strip().lower()
    ssa = t.endswith('_ssa')
    base = t[:-4] if ssa else t
    return _norm_level(base), ssa


# The SSA and the non-SSA form of one IL level use DIFFERENT operation sets. In Binary Ninja Function.llil / .mlil /
# .hlil are the non-SSA forms; their .ssa_form carries the *_SSA, *_PHI and MLIL *_ALIASED operations in place of the
# unversioned ones. The name rule below matches exactly the operations whose API class carries the SSA/Phi mixin
# (checked against the lowlevelil/mediumlevelil/highlevelil class definitions), plus LLIL_CALL_PARAM (its class is SSA:
# the parameter list of LLIL_CALL_SSA) and LLIL_REG_STACK_FREE_ABS_SSA (SSA by name; its class lacks the mixin).
_SSA_ONLY_OP_RE = re.compile(r'_SSA(?:_|$)|_PHI$|_ALIASED(?:_FIELD)?$')
_SSA_ONLY_OP_EXTRA = frozenset({'LLIL_CALL_PARAM'})


def _ssa_only_op(name):
    return bool(_SSA_ONLY_OP_RE.search(name)) or name in _SSA_ONLY_OP_EXTRA


def _ssa_counterpart(name, members):
    """The SSA operation that replaces the non-SSA operation `name` in the SSA form (MLIL_CALL -> MLIL_CALL_SSA,
    MLIL_VAR_FIELD -> MLIL_VAR_SSA_FIELD), or None. `members` = the level's operation enum names (None = unknown)."""
    if not members or _ssa_only_op(name):
        return None
    cands = [name + '_SSA']
    if name.endswith('_FIELD'):
        cands.append(name[:-len('_FIELD')] + '_SSA_FIELD')
    for x in cands:
        if x in members:
            return x
    return None


def _il_search_form_check(c, ops_f, lvl, ssa, members):
    """il_search: refuse an operation filter that cannot match the IL form being walked, instead of answering with a
    'complete' empty scan (a silent false negative).
    * non-SSA walk (il=llil|mlil|hlil, the default il=mlil): every SSA-only operation -> 400 BAD_ARGUMENT.
    * SSA walk (il=*_ssa), LLIL/MLIL: a non-SSA operation that has an SSA counterpart -> 400 (the SSA translation
      versions every register/variable/memory access; MLIL represents unversioned variables with *_ALIASED).
    * SSA walk, HLIL: only a WARNING. HLIL has no aliased operations, so an aliased variable can stay unversioned in
      HLIL-SSA (HLIL_VAR and the expressions built on it can legitimately occur there)."""
    il_name = lvl + ('_ssa' if ssa else '')
    if not ssa:
        bad = sorted(x for x in ops_f if _ssa_only_op(x))
        if bad:
            raise _bad('operation(s) %s exist only in the SSA form of %s: pass il=%s_ssa (il=%s walks the non-SSA '
                       'form, where they never occur)' % (', '.join(bad), lvl, lvl, il_name),
                       {'il': il_name, 'operations': bad, 'use_il': lvl + '_ssa'})
        return
    pairs = sorted((x, _ssa_counterpart(x, members)) for x in ops_f)
    pairs = [(x, y) for x, y in pairs if y]
    if not pairs:
        return
    txt = ', '.join('%s (SSA form: %s)' % (x, y) for x, y in pairs)
    if lvl == 'hlil':
        c.warn('il=%s matches only unversioned (aliased-variable) instances; the rest occur as the SSA operation '
               '(or use il=hlil): %s' % (il_name, txt))
        return
    raise _bad('operation(s) %s do not occur in the SSA form of %s: pass il=%s for the non-SSA form, or search the '
               'SSA operation' % (txt, lvl, lvl),
               {'il': il_name, 'operations': [x for x, _ in pairs], 'ssa_counterparts': [y for _, y in pairs],
                'use_il': lvl})


# il_search text_regex runs over the rendered text of every IL statement INSIDE the request's view lock, and a
# Python re search cannot be interrupted: one catastrophic search would hold the lock (every sibling request answers
# 503 BUSY) until Binary Ninja is restarted. Two guards, both decided before the scan starts:
#  * exponential backtracking is refused: a group repeated more than once whose body can itself vary (a nested
#    variable repetition, an alternation or a conditional), e.g. (\w+)+ or (a|ab)* -> 400 BAD_ARGUMENT;
#  * polynomial backtracking (several variable repetitions, back-references, written-out alternations) is bounded
#    by the text WINDOW the pattern runs on: the largest window from _RX_WINDOWS whose estimated worst-case step
#    count (_rx_cost: an estimate of the matcher's steps, not a time) stays within _RX_STEP_LIMIT; no window
#    fits -> 400 BAD_ARGUMENT. How long a step takes depends on the machine, so no time per statement is claimed.
# A statement longer than the window with no decided match inside it (no match, or a match that touches the window
# edge or depends on a lookahead, so the cut could change the answer) is counted (scan.regex_unsearched_tail_count)
# and makes the scan incomplete: its text beyond the window was NOT searched (never a silent false negative).
_RX_WINDOWS = (2000, 1000, 600, 400, 300, 200, 150, 120, 100, 80, 60, 40)
_RX_STEP_LIMIT = 5 * 10 ** 7
_RX_MAX_DEPTH = 200


def _rx_parser():
    """The stdlib regex parser module (re._parser on Python 3.11+, sre_parse before), or None."""
    try:
        from re import _parser as m      # Python 3.11+ (sre_parse is a deprecated alias there: never imported)
        return m
    except Exception:
        pass
    try:
        import sre_parse as m            # Python <= 3.10
        return m
    except Exception:
        return None


def _rx_opname(op):
    n = getattr(op, 'name', None)
    return n if isinstance(n, str) else str(op)


def _rx_seq(sp):
    d = getattr(sp, 'data', None)
    if isinstance(d, list):
        return d
    return sp if isinstance(sp, list) else []


def _rx_children(av):
    """The sub-patterns nested directly in one parsed token's argument (any shape: tuple, list, SubPattern)."""
    out, stack = [], [av]
    while stack:
        x = stack.pop()
        if isinstance(getattr(x, 'data', None), list):
            out.append(x)
        elif isinstance(x, (tuple, list)):
            stack.extend(x)
    return out


def _rx_repeat(name, av):
    """(lo, hi, body) of a repetition token, else None."""
    if name.endswith('REPEAT') and isinstance(av, (tuple, list)) and len(av) == 3:
        try:
            return int(av[0]), int(av[1]), av[2]
        except Exception:
            return None
    return None


def _rx_varies(seq, depth=0):
    """True when the parsed sequence can match in more than one way: a variable repetition, an alternation or a
    conditional anywhere in it (unknown shapes count as varying)."""
    if depth > _RX_MAX_DEPTH:
        return True
    for tok in seq:
        try:
            op, av = tok
        except Exception:
            return True
        name = _rx_opname(op)
        if name in ('BRANCH', 'GROUPREF_EXISTS'):
            return True
        rep = _rx_repeat(name, av)
        if rep is not None and rep[1] > rep[0]:
            return True
        for ch in _rx_children(av):
            if _rx_varies(_rx_seq(ch), depth + 1):
                return True
    return False


def _rx_profile(seq, prof, depth=0):
    """Collect prof['spans'] (hi - lo of every variable repetition), prof['grefs'] (back-references), prof['alts'] (the
    product of the alternation widths) and prof['lookahead']; set prof['nested'] to the first repeated group whose body
    varies (exponential backtracking)."""
    if depth > _RX_MAX_DEPTH:
        prof['nested'] = prof['nested'] or 'nesting deeper than %d levels' % _RX_MAX_DEPTH
        return
    for tok in seq:
        try:
            op, av = tok
        except Exception:
            prof['nested'] = prof['nested'] or 'an unrecognized parse token'
            return
        name = _rx_opname(op)
        if name.startswith('GROUPREF') and name != 'GROUPREF_EXISTS':
            prof['grefs'] += 1
        if name == 'BRANCH':
            # written-out alternations multiply the paths even without a repetition ((?:a|aa)(?:a|aa)...X)
            try:
                prof['alts'] = min(prof['alts'] * max(1, len(av[1])), 10 ** 15)
            except Exception:
                prof['alts'] = min(prof['alts'] * 2, 10 ** 15)
        elif name == 'GROUPREF_EXISTS':
            prof['alts'] = min(prof['alts'] * 2, 10 ** 15)
        if name in ('ASSERT', 'ASSERT_NOT'):
            try:
                if int(av[0]) >= 0:
                    prof['lookahead'] = True
            except Exception:
                prof['lookahead'] = True
        rep = _rx_repeat(name, av)
        if rep is not None:
            lo, hi, body = rep
            if hi > lo:
                prof['spans'].append(hi - lo)
            if hi > 1 and _rx_varies(_rx_seq(body), depth + 1) and not prof['nested']:
                prof['nested'] = 'a repetition (max %s) of a sub-pattern that can itself vary' % (
                    'unbounded' if hi >= 65535 else hi)
        for ch in _rx_children(av):
            _rx_profile(_rx_seq(ch), prof, depth + 1)


def _rx_profile_textual(rs):
    """Fallback when the stdlib parser is unavailable: a conservative scan of the pattern text. Every quantified
    group is treated as nested, and every quantifier as an unbounded variable repetition."""
    prof = {'spans': [], 'grefs': 0, 'nested': None, 'lookahead': '(?=' in rs or '(?!' in rs, 'alts': 1}
    s = re.sub(r'\\[1-9]', '\x01', rs)                            # back-references
    s = re.sub(r'\\.', 'e', s)                                     # other escapes
    s = re.sub(r'\[\^?\]?[^\]]*\]', 'c', s)                        # character classes
    s = s.replace('(?', '(')                                       # group prefixes are not quantifiers
    if re.search(r'\)(?:[*+]|\{\d*,?\d*\})', s):
        prof['nested'] = 'a quantified group (the regex parser is unavailable: every quantified group is refused)'
    prof['grefs'] = s.count('\x01')
    prof['spans'] = [1 << 32] * (len(re.findall(r'[*+?]|\{\d*,?\d*\}', s)))
    prof['alts'] = 2 ** min(s.count('|'), 50)
    return prof


def _rx_cost(n, spans, grefs, alts=1):
    """Estimated worst-case backtracking steps of one search over n characters: the ways k variable repetitions can
    split the text, summed over every start position (at most n * prod(span + 1), and at most C(n+k+1, k+1) because
    the repetitions share the remaining text), times n per back-reference, times the product of the alternation
    widths (alts)."""
    k = len(spans)
    ways = n
    for s in spans:
        ways *= min(s, n) + 1
    if k:
        ways = min(ways, math.comb(n + k + 1, k + 1))
    return ways * (n + 1) ** grefs * max(1, alts)


def _text_regex_window(rs):
    """(window, lookahead) for il_search text_regex, or BAD_ARGUMENT (see _RX_WINDOWS). window = the characters of
    each statement the pattern runs over; lookahead = the pattern looks ahead, so a match found inside the window of
    a longer statement is not decided by the window alone."""
    mod = _rx_parser()
    prof = None
    if mod is not None:
        try:
            prof = {'spans': [], 'grefs': 0, 'nested': None, 'lookahead': False, 'alts': 1}
            _rx_profile(_rx_seq(mod.parse(rs)), prof)
        except Exception:
            prof = None
    if prof is None:
        prof = _rx_profile_textual(rs)
    if prof['nested']:
        raise _bad('text_regex is refused: it contains %s (for example (\\w+)+ or (a|ab)*), whose backtracking can be '
                   'exponential; a regex search cannot be interrupted and would hold this binary\'s lock. Drop the '
                   'outer repetition (\\w+ instead of (\\w+)+) or search the parts separately' % prof['nested'],
                   {'text_regex': _clip(rs, 200)})
    for n in _RX_WINDOWS:
        if _rx_cost(n, prof['spans'], prof['grefs'], prof['alts']) <= _RX_STEP_LIMIT:
            return n, bool(prof['lookahead'])
    raise _bad('text_regex is refused: its %d variable-length repetition(s), %d back-reference(s) and alternations '
               '(%d combined paths) can backtrack polynomially beyond the scan limit even over a %d-character '
               'statement; use fewer .* / \\w+ / \\s* style repetitions or alternations (anchor with literals), or '
               'narrow with operation, callee or constant'
               % (len(prof['spans']), prof['grefs'], prof['alts'], _RX_WINDOWS[-1]), {'text_regex': _clip(rs, 200)})


def _stmt_text(ins):
    try:
        return str(ins)
    except Exception:
        return '<unrenderable>'


def il_search(ops, bv, p):
    c = _Ctx(p, 90)
    lvl, ssa = _parse_il_level(c.s('il', 'mlil'))
    prefix = lvl.upper() + '_'
    generate = c.b('generate', False)
    ops_f = set()
    for tok in [x.strip() for x in c.s('operation', '').split(',') if x.strip()]:
        t = tok.upper()
        if not re.match(r'^(?:LLIL|MLIL|HLIL)_', t):
            t = prefix + t
        if not t.startswith(prefix):
            raise _bad('operation %s does not belong to il=%s' % (tok, lvl))
        ops_f.add(t)
    if ops_f:
        enum_name = {'llil': 'LowLevelILOperation', 'mlil': 'MediumLevelILOperation',
                     'hlil': 'HighLevelILOperation'}[lvl]
        members = None
        try:
            from binaryninja import enums as _e
            members = set(getattr(_e, enum_name).__members__)
            unknown = sorted(x for x in ops_f if x not in members)
            if unknown:
                raise _bad('unknown %s operation(s): %s' % (lvl, ', '.join(unknown)))
        except rc.ApiError:
            raise
        except Exception:
            members = None
        _il_search_form_check(c, ops_f, lvl, ssa, members)
    callees = set()
    for x in [x.strip() for x in c.s('callee', '').split(',') if x.strip()]:
        callees |= _name_variants(x)
    const = None
    cs = c.s('constant', '').strip()
    if cs:
        try:
            if re.fullmatch(r'-?0[xX][0-9a-fA-F]+', cs):
                const = int(cs, 16)
            elif re.fullmatch(r'-?0[nN][0-9]+', cs):
                const = int(cs.replace('0n', '').replace('0N', ''), 10)
            elif re.fullmatch(r'-?[0-9]+', cs):
                const = int(cs, 10)
            else:
                raise ValueError(cs)
        except Exception:
            raise _bad('constant must be 0x<hex>, 0n<decimal> or a decimal integer (got %r)' % _clip(cs, 40))
    rx = None
    rx_window = None
    rx_lookahead = False
    rs = c.s('text_regex', '')
    if rs:
        if len(rs) > 200:
            raise _bad('text_regex longer than 200 characters')
        try:
            rx = re.compile(rs)
        except Exception as e:
            raise _bad('text_regex does not compile: %s' % _clip(e, 160))
        rx_window, rx_lookahead = _text_regex_window(rs)     # BAD_ARGUMENT for catastrophic-backtracking shapes
    if not (ops_f or callees or const is not None or rx is not None):
        raise _bad('give at least one filter: operation, callee, constant or text_regex')
    offset = c.i('offset', 0, 0, 10 ** 7)
    limit = c.i('limit', 200, 1, 5000)
    max_functions = c.i('max_functions', 2000, 1, 50000)
    fn_param = c.s('function', '').strip()
    if fn_param:
        funcs = [resolve_function_strict(bv, fn_param)]
    else:
        funcs = _sorted_functions(bv)
        fromf = c.s('from_function', '').strip()
        if fromf:
            fa = _parse_num(fromf, 'function address')
            if fa is None:
                raise _bad('from_function must be 0x<hex> or 0n<decimal>')
            funcs = [f for f in funcs if int(f.start) > fa]
    total_funcs = len(funcs)
    scope_cut = False
    if len(funcs) > max_functions:
        funcs = funcs[:max_functions]
        scope_cut = True
        c.warn('max_functions=%d reached: only the first %d of %d functions (by start) were scanned; continue '
               'with from_function=%s' % (max_functions, max_functions, total_funcs, _hx(funcs[-1].start)))
    need = offset + limit + 1
    names = {}
    matches = []
    skipped = []
    scanned = 0
    stop = False
    resume_from = None
    partial = None
    rx_tail_count = 0
    rx_tail = []
    has_node_filter = bool(ops_f or callees or const is not None)

    def node_ok(n):
        opn = _op(n)
        if ops_f and opn not in ops_f:
            return None
        if const is not None:
            if opn not in _CONST_OPS:
                return None
            v = _const_val(n)
            if v is None or (v != const and (v & 0xFFFFFFFFFFFFFFFF) != (const & 0xFFFFFFFFFFFFFFFF)):
                return None
        if callees:
            if not _CALL_OP_RE.match(opn):
                return None
            a = _dest_addr(n)
            nm = _name_at(bv, a, names) if a is not None else None
            if not nm or not (_name_variants(nm) & callees):
                return None
        return n

    for f in funcs:
        if c.expired():
            stop = True
            resume_from = _hx(int(f.start) - 1)
            c.warn('time-budget: scan stopped before %s@%s; continue with from_function=%s (functions starting '
                   'after that address are scanned)' % (f.name, _hx(f.start), resume_from))
            break
        if fn_param:
            ilf = il_of(f, lvl, ssa, generate)
        else:
            try:
                ilf = il_of(f, lvl, ssa, generate)
            except rc.ApiError:
                skipped.append('%s@%s' % (f.name, _hx(f.start)))
                continue
        scanned += 1
        seen = set()
        n_before = len(matches)
        tail_before = (rx_tail_count, len(rx_tail))
        n_stmt = 0
        cut_here = False
        try:
            for ins in ilf.instructions:
                # the budget is also checked per statement: one large function must not run the call past it
                if c.expired():
                    cut_here = True
                    break
                n_stmt += 1
                stmt_text = None
                if rx is not None:
                    stmt_text = _stmt_text(ins)
                    m = rx.search(stmt_text[:rx_window])
                    if m is not None and len(stmt_text) > rx_window and (rx_lookahead or m.end() >= rx_window - 1):
                        # undecided: the cut can change this answer ($, \b, \Z or a lookahead read past the window)
                        m = None
                    if m is None:
                        if len(stmt_text) > rx_window:
                            rx_tail_count += 1
                            if len(rx_tail) < 20:
                                ta = _addr_of(ins, None)
                                rx_tail.append('%s@%s' % (f.name, _hx(ta) if ta is not None else _hx(f.start)))
                        continue
                hits = list(ins.traverse(node_ok)) if has_node_filter else [ins]
                for n in hits:
                    try:
                        k = int(n.expr_index)
                    except Exception:
                        k = id(n)
                    if k in seen:
                        continue
                    seen.add(k)
                    a = _addr_of(n, _addr_of(ins, None))
                    matches.append({
                        'function': f.name, 'function_start': _hx(f.start), 'va': _hx(a) if a is not None else None,
                        'sym': sym(bv, a, f) if a is not None else None, 'op': _op(n),
                        'node': _text(n, 200), 'statement': stmt_text[:300] if stmt_text else _text(ins, 300),
                        'instr_index': getattr(ins, 'instr_index', None),
                    })
                    if len(matches) >= need:
                        stop = True
                        break
                if stop:
                    break
        except Exception as e:
            c.warn('IL walk failed in %s@%s: %s' % (f.name, _hx(f.start), _clip(e, 120)))
        if cut_here:
            stop = True
            if not fn_param and scanned > 1:
                # an earlier function of this call was completed, so a resume still makes progress: drop this
                # function's partial matches and resume AT it (exactly as if the budget had run out before it)
                del matches[n_before:]
                rx_tail_count = tail_before[0]
                del rx_tail[tail_before[1]:]
                scanned -= 1
                resume_from = _hx(int(f.start) - 1)
                c.warn('time-budget: scan stopped inside %s@%s (its matches are not reported; it is scanned again on '
                       'resume); continue with from_function=%s (functions starting after that address are scanned)'
                       % (f.name, _hx(f.start), resume_from))
            else:
                # the first function of this call (or the only one asked for) did not finish within the budget: keep
                # what was found, and say that the rest of it was NOT searched
                partial = {'function': f.name, 'function_start': _hx(f.start), 'statements_searched': n_stmt}
                if fn_param:
                    c.warn('time-budget: only the first %d statement(s) of %s@%s were searched; the rest of it was NOT '
                           'searched (raise time_budget_s up to scan_time_budget_s, or narrow the filter)'
                           % (n_stmt, f.name, _hx(f.start)))
                else:
                    resume_from = _hx(int(f.start))
                    c.warn('time-budget: only the first %d statement(s) of %s@%s were searched and the rest of it was '
                           'NOT searched (search it alone: function=%s with a larger time_budget_s); continue the scan '
                           'with from_function=%s' % (n_stmt, f.name, _hx(f.start), _hx(f.start), resume_from))
        if stop:
            break
    if rx_tail_count:
        c.warn('%d statement(s) are longer than the %d-character text_regex window (set by the variable-length '
               'repetitions in text_regex) and had no decided match inside it: their text beyond the window was NOT '
               'searched (listed in scan.regex_unsearched_tail; use fewer repetitions for a wider window, or read '
               'those statements with bn_decompile)' % (rx_tail_count, rx_window))
    page = matches[offset:offset + limit]
    more = len(matches) > offset + limit
    nxt = offset + limit if more else None
    timed_out = resume_from is not None
    gap = timed_out or partial is not None or rx_tail_count > 0
    return c.out({
        'il': lvl + ('_ssa' if ssa else ''), 'generate': generate, 'matches': page,
        'scan': {'functions_total': total_funcs, 'functions_scanned': scanned, 'skipped_no_il_count': len(skipped),
                 'skipped_no_il': skipped[:200], 'complete': not (scope_cut or gap),
                 'resume_from_function': resume_from, 'partial_function': partial,
                 'regex_window_chars': rx_window, 'regex_unsearched_tail_count': rx_tail_count,
                 'regex_unsearched_tail': rx_tail},
        'note': None if not skipped or generate else (
            '%d function(s) had no %s yet and were skipped (listed); pass generate=1 to build their IL'
            % (len(skipped), lvl)),
    }, truncated=more or scope_cut or gap, next_offset=nxt)


def _find_vars_by_name(func, ssa_il, name):
    found = {}
    pool = []
    for src in ('vars', 'parameter_vars'):
        try:
            pool.extend(list(getattr(func, src)))
        except Exception:
            pass
    try:
        for sv in ssa_il.ssa_vars:
            pool.append(sv.var)
    except Exception:
        pass
    for v in pool:
        try:
            if v.name == name:
                found[_vkey(v)] = v
        except Exception:
            continue
    return [found[k] for k in sorted(found, key=str)]


def _ssa_versions_of(ssa_il, var):
    k = _vkey(var)
    vers = {}
    try:
        for sv in ssa_il.ssa_vars:
            if _vkey(sv.var) == k:
                vers[int(sv.version)] = sv
    except Exception:
        pass
    return vers


def _ssa_target(c, bv, mode):
    """Resolve (func, ssa_il, [SSAVariable]) for ssa_def / ssa_uses."""
    f = resolve_function_strict(bv, c.req('function'))
    ssa_il = il_of(f, 'mlil', True, c.b('generate', True))
    raw = c.req('var')
    version = c.i('version', -1, -1, 10 ** 6, strict=True)
    m = re.match(r'^(.*)#([0-9]+)$', raw)
    if m:
        raw, vv = m.group(1), int(m.group(2))
        if version >= 0 and version != vv:
            raise _bad('var %s#%d conflicts with version=%d' % (raw, vv, version))
        version = vv
    vs = _find_vars_by_name(f, ssa_il, raw)
    if not vs:
        raise rc.NotFoundError('variable', raw, None)
    if len(vs) > 1:
        raise rc.AmbiguousError('variable', raw, [{'name': '%s (%s %s)' % (v.name, _var_storage_kind(v),
                                                                              _hx(getattr(v, 'storage', 0))),
                                                   'start': _hx(f.start)} for v in vs])
    var = vs[0]
    vers = _ssa_versions_of(ssa_il, var)
    at = c.s('at_va', '').strip()
    if version < 0 and at:
        va = parse_va(bv, at)
        reads, writes = set(), set()
        for st in mlil_ssa_at(f, va):
            for sv in (getattr(st, 'vars_read', None) or []):
                if hasattr(sv, 'version') and _vkey(sv.var) == _vkey(var):
                    reads.add(int(sv.version))
            for sv in (getattr(st, 'vars_written', None) or []):
                if hasattr(sv, 'version') and _vkey(sv.var) == _vkey(var):
                    writes.add(int(sv.version))
        prefer, other = (reads, writes) if mode == 'def' else (writes, reads)
        pick = prefer or other
        if not pick:
            raise rc.NotFoundError('SSA version of %s at' % raw, _hx(va), None)
        if len(pick) > 1:
            raise rc.AmbiguousError('SSA version of %s at' % raw, _hx(va),
                                    [{'name': '%s#%d' % (raw, x), 'start': _hx(va)} for x in sorted(pick)])
        version = sorted(pick)[0]
    if version >= 0:
        sv = vers.get(version)
        if sv is None:
            try:
                from binaryninja.mediumlevelil import SSAVariable
                sv = SSAVariable(var, version)
            except Exception:
                raise rc.NotFoundError('SSA version', '%s#%d' % (raw, version), ['%s#%d' % (raw, x)
                                                                                 for x in sorted(vers)][:50])
        return f, ssa_il, [sv]
    if not vers:
        raise rc.NotFoundError('SSA versions of', raw, None)
    return f, ssa_il, [vers[k] for k in sorted(vers)]


def _site_json(bv, f, ins):
    a = _addr_of(ins)
    return {'va': _hx(a) if a is not None else None, 'sym': sym(bv, a, f) if a is not None else None,
            'op': _op(ins), 'text': _text(ins), 'instr_index': getattr(ins, 'instr_index', None)}


def ssa_def(ops, bv, p):
    c = _Ctx(p, 30)
    f, ssa_il, svs = _ssa_target(c, bv, 'def')
    params = _param_keys(f)
    out = []
    cut = len(svs) > 200
    for sv in svs[:200]:
        try:
            d = ssa_il.get_ssa_var_definition(sv)
        except Exception as e:
            d = None
            c.warn('definition lookup failed for %s: %s' % (_svname(sv), _clip(e, 100)))
        row = {'var': _svname(sv), 'version': int(sv.version), 'definition': _site_json(bv, f, d) if d is not None
               else None}
        if d is None:
            pk = params.get(_vkey(sv.var))
            row['origin'] = ('param[%d] (entry value)' % pk) if (pk is not None and int(sv.version) == 0) else (
                'entry-or-uninit (version 0, not a parameter)' if int(sv.version) == 0 else 'no definition found')
        out.append(row)
    return c.out({'function': _fref(f), 'versions': out}, truncated=cut)


def ssa_uses(ops, bv, p):
    c = _Ctx(p, 30)
    f, ssa_il, svs = _ssa_target(c, bv, 'uses')
    limit = c.i('limit', 500, 1, 5000)
    out = []
    total = 0
    cut = False
    for sv in svs[:200]:
        try:
            uses = list(ssa_il.get_ssa_var_uses(sv))
        except Exception as e:
            uses = []
            c.warn('uses lookup failed for %s: %s' % (_svname(sv), _clip(e, 100)))
        rows = []
        for u in uses:
            if total >= limit:
                cut = True
                break
            rows.append(_site_json(bv, f, u))
            total += 1
        out.append({'var': _svname(sv), 'version': int(sv.version), 'use_count': len(uses), 'uses': rows})
        if cut:
            break
    if len(svs) > 200:
        cut = True
    return c.out({'function': _fref(f), 'versions': out}, truncated=cut)


def _call_at(bv, f, va, ssa=True):
    stmts = mlil_at(f, va, ssa, True)
    calls = [s for s in stmts if _is_call(s)]
    if not calls:
        raise _bad('no MLIL%s call statement at %s in %s@%s (statements there: %s)'
                   % ('-SSA' if ssa else '', _hx(va), f.name, _hx(f.start),
                      '; '.join(_text(s, 80) for s in stmts[:4]) or 'none'))
    if len(calls) > 1:
        raise rc.AmbiguousError('call at', _hx(va), [{'name': _text(s, 120), 'start': _hx(va)} for s in calls])
    return calls[0]


def _classify_leaf(bv, node):
    opn = _op(node)
    v = _const_val(node)
    if opn.endswith('_IMPORT'):
        return {'kind': 'import', 'value': _hx(v), 'name': _name_at(bv, v) if v is not None else None}
    if opn.endswith('_CONST_PTR') or opn.endswith('_EXTERN_PTR'):
        return {'kind': 'global', 'value': _hx(v), 'name': _name_at(bv, v) if v is not None else None}
    return {'kind': 'const', 'value': _hx(v), 'text': _text(node, 120)}


def backward_slice(ops, bv, p):
    """MLIL-SSA backward slice of one call argument (worklist; phi; one syntactic memory hop)."""
    c = _Ctx(p, 30)
    va = parse_va(bv, c.req('call_site'))
    argi = c.i('arg_index', 0, 0, 1024, strict=True)
    f = _func_for_va(bv, va, c.s('function', ''))
    max_depth = c.i('max_depth', 24, 1, 64)
    max_nodes = c.i('max_nodes', 200, 1, 2000)
    ssa_il = il_of(f, 'mlil', True, True)
    call = _call_at(bv, f, va, True)
    try:
        params = list(call.params)
    except Exception:
        params = []
    if argi >= len(params):
        raise _bad('arg_index %d is out of range: the call at %s has %d parameter(s) in MLIL-SSA'
                   % (argi, _hx(va), len(params)))
    seed = params[argi]
    pkeys = _param_keys(f)
    blind = set(_SLICE_BLIND_SPOTS)
    nodes = []
    sources = []
    visited = set()
    truncated = False
    q = collections.deque()

    def add_node(kind, parent, depth, var=None, ins=None, extra=None):
        n = {'id': len(nodes), 'parent': parent, 'depth': depth, 'kind': kind}
        if var is not None:
            n['var'] = _svname(var)
        if ins is not None:
            n.update({'va': _hx(_addr_of(ins)) if _addr_of(ins) is not None else None,
                      'sym': sym(bv, _addr_of(ins), f) if _addr_of(ins) is not None else None,
                      'op': _op(ins), 'text': _text(ins)})
        if extra:
            n.update(extra)
        nodes.append(n)
        return n['id']

    def expand_expr(expr, parent, depth, role):
        """Queue every SSA var read in expr; constants / globals / loads become sources."""
        loads = _nodes(expr, _LOAD_SSA_OPS)
        load_addr_ids = set()
        for ld in loads:
            try:
                for n in ld.src.traverse(lambda x: x):
                    load_addr_ids.add(int(n.expr_index))
            except Exception:
                pass
        for node, sv in _ssa_reads(expr):
            try:
                r = 'load-address' if int(node.expr_index) in load_addr_ids else role
            except Exception:
                r = role
            if _op(node).startswith('MLIL_VAR_ALIASED'):
                blind.add('aliased (address-taken) variables are memory-backed: their writes through pointers '
                          'are not modelled')
            q.append((sv, depth, parent, r))
        for ld in loads:
            memory_hop(ld, parent, depth)
        if not loads and not _ssa_reads(expr):
            for leaf in _nodes(expr, _CONST_OPS):
                s = _classify_leaf(bv, leaf)
                s.update({'via_node': parent, 'role': role})
                sources.append(s)
        for ao in _nodes(expr, frozenset({'MLIL_ADDRESS_OF', 'MLIL_ADDRESS_OF_FIELD'})):
            sources.append({'kind': 'address-of', 'text': _text(ao, 120), 'via_node': parent, 'role': role})

    def memory_hop(ld, parent, depth):
        addr_expr = getattr(ld, 'src', None)
        fixed = addr_expr is not None and _op(addr_expr) in _ADDR_CONST_OPS
        src_mem = getattr(ld, 'src_memory', None)
        mdef = None
        try:
            if src_mem is not None:
                mdef = ssa_il.get_ssa_memory_definition(int(src_mem))
        except Exception:
            mdef = None
        hop_ok = False
        if mdef is not None and _op(mdef) in _STORE_SSA_OPS:
            try:
                same = str(mdef.dest) == str(addr_expr)
                if same and _op(ld) == 'MLIL_LOAD_STRUCT_SSA':
                    same = _op(mdef) == 'MLIL_STORE_STRUCT_SSA' and int(mdef.offset) == int(ld.offset)
                elif same:
                    same = _op(mdef) == 'MLIL_STORE_SSA'
                hop_ok = bool(same)
            except Exception:
                hop_ok = False
        if hop_ok:
            nid = add_node('memory-store', parent, depth + 1, ins=mdef,
                           extra={'load': _text(ld, 160), 'mem_version': src_mem})
            if depth + 1 < max_depth:
                expand_expr(mdef.src, nid, depth + 1, 'stored-value')
            else:
                blind.add('max_depth reached')
            return
        src = {'kind': 'global' if fixed else 'memory', 'load': _text(ld, 160), 'via_node': parent,
               'mem_version': src_mem}
        if mdef is not None:
            src['mem_def'] = {'op': _op(mdef), 'va': _hx(_addr_of(mdef)), 'text': _text(mdef, 160)}
        sources.append(src)

    root = add_node('seed', None, 0, ins=call, extra={'arg_index': argi, 'arg': _text(seed, 200)})
    if _op(seed) in _CONST_OPS:
        s = _classify_leaf(bv, seed)
        s.update({'via_node': root, 'role': 'argument'})
        sources.append(s)
    else:
        expand_expr(seed, root, 0, 'argument')
    while q:
        if c.expired():
            truncated = True
            c.warn('time-budget: slice stopped with %d queued item(s)' % len(q))
            break
        sv, depth, parent, role = q.popleft()
        k = _svkey(sv)
        if k in visited:
            continue
        if len(nodes) >= max_nodes:
            truncated = True
            c.warn('max_nodes=%d reached' % max_nodes)
            break
        if depth + 1 > max_depth:
            truncated = True
            blind.add('max_depth reached')
            continue
        visited.add(k)
        try:
            d = ssa_il.get_ssa_var_definition(sv)
        except Exception:
            d = None
        if d is None:
            pk = pkeys.get(_vkey(sv.var))
            if pk is not None and int(sv.version) == 0:
                nid = add_node('param', parent, depth + 1, var=sv, extra={'role': role, 'param_index': pk})
                sources.append({'kind': 'param', 'index': pk, 'var': _svname(sv), 'via_node': nid})
            else:
                nid = add_node('entry-or-uninit', parent, depth + 1, var=sv, extra={'role': role})
                sources.append({'kind': 'entry-or-uninit', 'var': _svname(sv), 'via_node': nid,
                                'storage': _var_storage_kind(sv.var)})
            continue
        opn = _op(d)
        if opn == 'MLIL_VAR_PHI':
            nid = add_node('phi', parent, depth + 1, var=sv, ins=d, extra={'role': role})
            try:
                for s2 in d.src:
                    q.append((s2, depth + 1, nid, 'phi-input'))
            except Exception:
                pass
        elif opn in _SSA_SET_OPS:
            nid = add_node('assign', parent, depth + 1, var=sv, ins=d, extra={'role': role})
            try:
                expand_expr(d.src, nid, depth + 1, 'assigned-value')
            except Exception:
                pass
            if opn in ('MLIL_SET_VAR_SSA_FIELD', 'MLIL_SET_VAR_ALIASED_FIELD'):
                prev = getattr(d, 'prev', None)
                if prev is not None and hasattr(prev, 'version'):
                    q.append((prev, depth + 1, nid, 'partial-write-prev'))
        elif _is_call(d):
            a, nm = _callee_name(bv, d)
            nid = add_node('call_return', parent, depth + 1, var=sv, ins=d, extra={'role': role, 'callee': nm})
            sources.append({'kind': 'call_return', 'callee': nm, 'callee_va': _hx(a) if a is not None else None,
                            'va': _hx(_addr_of(d)), 'via_node': nid})
        else:
            nid = add_node('other', parent, depth + 1, var=sv, ins=d, extra={'role': role})
            sources.append({'kind': 'other', 'op': opn, 'text': _text(d, 160), 'via_node': nid})
    return c.out({
        'function': _fref(f), 'call_site': {'va': _hx(va), 'sym': sym(bv, va, f), 'text': _text(call)},
        'arg_index': argi, 'seed': _text(seed, 200), 'nodes': nodes, 'sources': sources,
        'blind_spots': sorted(blind),
        'note': 'every node carries va + MLIL-SSA text, so it can be cited; a slice is a LEAD, not a proof',
    }, truncated=truncated)


def _dfq_options(c):
    raw = [x.strip() for x in c.s('options', '').split(',') if x.strip()]
    names = []
    for r in raw:
        n = _DFQ_ALIASES.get(r.lower())
        if n is None:
            raise _bad('unknown dataflow option %r (use from_lookup_table, allow_writable)' % _clip(r, 40))
        if n not in names:
            names.append(n)
    enum_vals = []
    if names:
        try:
            from binaryninja.enums import DataFlowQueryOption
            enum_vals = [getattr(DataFlowQueryOption, n) for n in names]
        except Exception:
            raise _api('UNSUPPORTED_API', 'DataFlowQueryOption is not available in this Binary Ninja build', 501)
    return names, enum_vals


def _complexity(ssa_il):
    total = 0
    try:
        for b in ssa_il.basic_blocks:
            total += len(b.outgoing_edges)
    except Exception:
        return None
    return total


def possible_values(ops, bv, p):
    """Value sets at va; the DataFlowQueryOption flags are opt-in and echoed; REFUSED_COMPLEXITY above max."""
    c = _Ctx(p, 30)
    va = parse_va(bv, c.req('va'))
    f = _func_for_va(bv, va, c.s('function', ''))
    when = c.s('when', 'before').strip().lower() or 'before'
    if when not in ('before', 'after'):
        raise _bad('when must be before or after')
    opt_names, opt_vals = _dfq_options(c)
    max_cx = c.i('max_complexity', 20000, 1, 1000000)
    ssa_il = il_of(f, 'mlil', True, True)
    cx = _complexity(ssa_il)
    if cx is not None and cx > max_cx:
        raise _api('REFUSED_COMPLEXITY', 'function CFG complexity %d (sum of outgoing MLIL-SSA edges) exceeds '
                   'max_complexity=%d; raise max_complexity explicitly if the query is worth the cost'
                   % (cx, max_cx), 422, {'complexity': cx, 'max_complexity': max_cx})
    operand = c.s('operand', '').strip()
    varname = c.s('var', '').strip()
    if operand and varname:
        raise _bad('give operand OR var, not both')
    stmts = mlil_ssa_at(f, va)
    if not stmts:
        raise rc.NotFoundError('MLIL-SSA statement at', _hx(va), ['no MLIL statement maps to this address; try the '
                                                                   'call/branch instruction address'])
    results = []
    for st in stmts:
        row = {'instr_index': getattr(st, 'instr_index', None), 'va': _hx(_addr_of(st)), 'text': _text(st),
               'values': []}
        try:
            if varname:
                vs = _find_vars_by_name(f, ssa_il, varname)
                if not vs:
                    raise rc.NotFoundError('variable', varname, None)
                if len(vs) > 1:
                    raise rc.AmbiguousError('variable', varname, [{'name': '%s (%s)' % (v.name, _var_storage_kind(v)),
                                                                   'start': _hx(f.start)} for v in vs])
                var = vs[0]
                pool = getattr(st, 'vars_written' if when == 'after' else 'vars_read', None) or []
                svs = [sv for sv in pool if hasattr(sv, 'version') and _vkey(sv.var) == _vkey(var)]
                if not svs:
                    try:
                        nst = st.non_ssa_form
                        ver = (nst.get_ssa_var_version_after(var) if when == 'after'
                               else nst.get_ssa_var_version(var))
                        from binaryninja.mediumlevelil import SSAVariable
                        svs = [SSAVariable(var, int(ver))]
                    except Exception:
                        svs = []
                if not svs:
                    raise rc.NotFoundError('SSA version of %s at' % varname, _hx(va), None)
                for sv in svs:
                    v = st.get_ssa_var_possible_values(sv, opt_vals)
                    row['values'].append({'target': 'var:' + _svname(sv), 'value': serialize_pvs(v)})
            elif operand:
                m = re.match(r'^(?:param|arg):([0-9]+)$', operand, re.IGNORECASE)
                if m:
                    if not _is_call(st):
                        continue
                    ps = list(st.params)
                    ix = int(m.group(1))
                    if ix >= len(ps):
                        raise _bad('%s: the call has %d parameter(s)' % (operand, len(ps)))
                    v = ps[ix].get_possible_values(opt_vals)
                    row['values'].append({'target': operand.lower(), 'expr': _text(ps[ix], 160),
                                          'value': serialize_pvs(v)})
                elif operand.lower() in ('src', 'dest', 'condition', 'left', 'right'):
                    sub = getattr(st, operand.lower(), None)
                    if sub is None or not hasattr(sub, 'get_possible_values'):
                        continue
                    v = sub.get_possible_values(opt_vals)
                    row['values'].append({'target': operand.lower(), 'expr': _text(sub, 160),
                                          'value': serialize_pvs(v)})
                else:
                    reg = operand[4:] if operand.lower().startswith('reg:') else operand
                    nst = st.non_ssa_form
                    v = (nst.get_possible_reg_values_after(reg, opt_vals) if when == 'after'
                         else nst.get_possible_reg_values(reg, opt_vals))
                    row['values'].append({'target': 'reg:' + reg, 'value': serialize_pvs(v)})
            else:
                v = st.get_possible_values(opt_vals)
                row['values'].append({'target': 'expr', 'value': serialize_pvs(v)})
                if _is_call(st):
                    for ix, pe in enumerate(list(st.params)[:16]):
                        row['values'].append({'target': 'param:%d' % ix, 'expr': _text(pe, 160),
                                              'value': serialize_pvs(pe.get_possible_values(opt_vals))})
        except Exception as e:
            if _is_rc_error(e):
                raise
            row['error'] = _clip(e, 200)
        results.append(row)
    if operand and not any(r['values'] for r in results):
        raise _bad('operand %r does not apply to the statement(s) at %s' % (operand, _hx(va)))
    return c.out({
        'function': _fref(f), 'va': _hx(va), 'when': when, 'options_used': opt_names, 'complexity': cx,
        'statements': results,
        'note': 'undetermined=true means BN dataflow could not bound the value (a first-pass filter: a '
                'determined value is a cheap drop candidate for RANKING, never a refutation)',
    })


def branch_dependence(ops, bv, p):
    c = _Ctx(p, 20)
    va = parse_va(bv, c.req('va'))
    f = _func_for_va(bv, va, c.s('function', ''))
    mil = il_of(f, 'mlil', False, True)
    stmts = mlil_at(f, va, False, True)
    if not stmts:
        raise rc.NotFoundError('MLIL statement at', _hx(va), None)
    out = []
    for st in stmts:
        deps = []
        try:
            bd = st.branch_dependence
            for bi in sorted(bd):
                b = _il_get(mil, int(bi))
                dep = bd[bi]
                row = {'branch_instr_index': int(bi), 'dependence': getattr(dep, 'name', str(dep))}
                if b is not None:
                    row.update({'va': _hx(_addr_of(b)), 'sym': sym(bv, _addr_of(b), f) if _addr_of(b) is not None
                                else None, 'text': _text(b, 200)})
                    cond = getattr(b, 'condition', None)
                    if cond is not None:
                        row['condition'] = _text(cond, 200)
                deps.append(row)
        except Exception as e:
            out.append({'instr_index': getattr(st, 'instr_index', None), 'text': _text(st), 'error': _clip(e, 200)})
            continue
        out.append({'instr_index': getattr(st, 'instr_index', None), 'va': _hx(_addr_of(st)), 'text': _text(st),
                    'dependences': deps})
    return c.out({'function': _fref(f), 'va': _hx(va), 'statements': out, 'caveat': _BRANCH_DEP_CAVEAT})


# ---------------------------------------------------------------------------------------------------------------
# verbs: CFG, dominance, reachability
# ---------------------------------------------------------------------------------------------------------------

def _edge_targets(d):
    out = []
    try:
        for e in d['bb'].outgoing_edges:
            try:
                ti = int(e.target.index)
            except Exception:
                ti = None
            out.append({'to': ti, 'type': getattr(getattr(e, 'type', None), 'name', str(getattr(e, 'type', ''))),
                        'back_edge': bool(getattr(e, 'back_edge', False))})
    except Exception:
        pass
    out.sort(key=lambda x: (-1 if x['to'] is None else x['to'], x['type']))
    return out


def cfg(ops, bv, p):
    c = _Ctx(p, 30)
    f = resolve_function_strict(bv, c.req('function'))
    level = c.s('level', 'disasm').strip().lower() or 'disasm'
    max_blocks = c.i('max_blocks', 500, 1, 20000)
    il, blocks = _blocks_of(f, level, True)
    out = []
    exits = 0
    for d in blocks[:max_blocks]:
        j = _block_json(d, il)
        j['edges'] = _edge_targets(d)
        if not j['edges']:
            exits += 1
        out.append(j)
    cut = len(blocks) > max_blocks
    return c.out({'function': _fref(f), 'level': level, 'block_count': len(blocks), 'blocks': out,
                  'exit_blocks_in_page': exits}, truncated=cut)


def dominators(ops, bv, p):
    c = _Ctx(p, 30)
    f = resolve_function_strict(bv, c.req('function'))
    kind = c.s('kind', 'dominators').strip().lower() or 'dominators'
    if kind not in _DOM_KINDS:
        raise _bad('kind must be one of %s' % ', '.join(_DOM_KINDS))
    level = c.s('level', 'disasm').strip().lower() or 'disasm'
    il, blocks = _blocks_of(f, level, True)
    d = _find_block(f, il, blocks, c.req('block_va'))
    by_index = {x['index']: x for x in blocks}
    try:
        val = getattr(d['bb'], kind)
    except Exception as e:
        raise _api('UNSUPPORTED_API', 'BasicBlock.%s is unavailable: %s' % (kind, _clip(e, 160)), 501)
    if val is None:
        res_blocks = []
    elif isinstance(val, (list, tuple, set)):
        res_blocks = list(val)
    else:
        res_blocks = [val]
    rows = []
    for b in res_blocks:
        try:
            ix = int(b.index)
        except Exception:
            continue
        x = by_index.get(ix)
        rows.append(_block_json(x, il) if x is not None else {'index': ix})
    rows.sort(key=lambda r: r.get('index', -1))
    exits = sum(1 for x in blocks if not _edge_targets(x))
    return c.out({'function': _fref(f), 'level': level, 'kind': kind, 'block': _block_json(d, il),
                  'result': rows, 'exit_block_count': exits, 'caveat': _POSTDOM_CAVEAT})


def reachable(ops, bv, p):
    """Constraint-graph reachability: BFS over the CFG after removing edges / all out-edges of
    validation blocks."""
    c = _Ctx(p, 30)
    f = resolve_function_strict(bv, c.req('function'))
    level = c.s('level', 'disasm').strip().lower() or 'disasm'
    il, blocks = _blocks_of(f, level, True)
    src = _find_block(f, il, blocks, c.req('from_va'))
    dst = _find_block(f, il, blocks, c.req('to_va'))
    removed = set()
    applied_edges = []
    for item in [x.strip() for x in c.s('removed_edges', '').split(',') if x.strip()]:
        m = re.match(r'^(.+?)\s*->\s*(.+)$', item)
        if not m:
            raise _bad('removed_edges items are <block>-><block> (got %r)' % _clip(item, 60))
        a = _find_block(f, il, blocks, m.group(1))
        b = _find_block(f, il, blocks, m.group(2))
        removed.add((a['index'], b['index']))
        applied_edges.append('#%d->#%d' % (a['index'], b['index']))
    cut_out = set()
    for item in [x.strip() for x in c.s('removed_out_of', '').split(',') if x.strip()]:
        cut_out.add(_find_block(f, il, blocks, item)['index'])
    by_index = {x['index']: x for x in blocks}
    succ = {}
    for x in blocks:
        succ[x['index']] = sorted({e['to'] for e in _edge_targets(x) if e['to'] is not None})
    parent = {src['index']: None}
    dq = collections.deque([src['index']])
    while dq:
        u = dq.popleft()
        if u == dst['index']:
            break
        if u in cut_out:
            continue
        for v in succ.get(u, []):
            if (u, v) in removed or v in parent:
                continue
            parent[v] = u
            dq.append(v)
    ok = dst['index'] in parent
    path = []
    if ok:
        k = dst['index']
        while k is not None:
            path.append(_block_json(by_index[k], il))
            k = parent[k]
        path.reverse()
    return c.out({'function': _fref(f), 'level': level, 'from': _block_json(src, il), 'to': _block_json(dst, il),
                  'reachable': ok, 'path': path, 'removed_edges_applied': sorted(applied_edges),
                  'removed_out_of_applied': ['#%d' % i for i in sorted(cut_out)], 'visited': len(parent),
                  'caveat': 'static CFG only (exceptions, indirect jumps without resolved targets and callers are '
                            'not modelled); a hint, not proof'})


# ---------------------------------------------------------------------------------------------------------------
# verbs: call graph
# ---------------------------------------------------------------------------------------------------------------

def callers(ops, bv, p):
    c = _Ctx(p, 30)
    root = resolve_function_strict(bv, c.req('function'))
    depth = c.i('depth', 1, 1, 4)
    max_nodes = c.i('max_nodes', 300, 1, 5000)
    nodes = [{'name': root.name, 'start': _hx(root.start), 'depth': 0}]
    seen = {int(root.start)}
    edges = []
    frontier = [root]
    cut = False
    for d in range(1, depth + 1):
        nxt = []
        for g in frontier:
            if c.expired():
                cut = True
                c.warn('time-budget')
                break
            for (cf, site, prov) in _callers_of(bv, g):
                if len(edges) >= 4 * max_nodes:
                    cut = True
                    break
                edges.append({'from': cf.name, 'from_start': _hx(cf.start), 'site': _hx(site),
                              'sym': sym(bv, site, cf), 'to': g.name, 'to_start': _hx(g.start), 'prov': prov})
                if int(cf.start) not in seen:
                    if len(nodes) >= max_nodes:
                        cut = True
                        continue
                    seen.add(int(cf.start))
                    nodes.append({'name': cf.name, 'start': _hx(cf.start), 'depth': d})
                    nxt.append(cf)
            if cut:
                break
        frontier = sorted(nxt, key=lambda x: int(x.start))
        if cut or not frontier:
            break
    data_refs = []
    try:
        drs = sorted(int(a) for a in bv.get_data_refs(int(root.start), max_items=21))
        data_refs = [{'va': _hx(a), 'sym': sym(bv, a)} for a in drs[:20]]
        if len(drs) > 20:
            c.warn('data_refs to the function start capped at 20')
    except Exception:
        pass
    return c.out({'function': _fref(root), 'nodes': nodes, 'edges': edges, 'data_refs_to_start': data_refs,
                  'blind_spots': ['indirect callers (function pointers, vtables, RPC/COM dispatch tables) are not '
                                  'call edges: see data_refs_to_start and bn_xrefs kind=data']}, truncated=cut)


def callees(ops, bv, p):
    c = _Ctx(p, 30)
    root = resolve_function_strict(bv, c.req('function'))
    depth = c.i('depth', 1, 1, 4)
    max_nodes = c.i('max_nodes', 300, 1, 5000)
    inc_imp = c.b('include_imports', True)
    cache = {}
    nodes = [{'name': root.name, 'start': _hx(root.start), 'depth': 0}]
    seen = {int(root.start)}
    imports = {}
    edges = []
    frontier = [root]
    cut = False
    for d in range(1, depth + 1):
        nxt = []
        for g in frontier:
            if c.expired():
                cut = True
                c.warn('time-budget')
                break
            for e in _edges(bv, g, cache):
                if e['prov'] == 'import' and not inc_imp:
                    continue
                if len(edges) >= 4 * max_nodes:
                    cut = True
                    break
                edges.append(_edge_json(bv, g, e))
                if e['prov'] == 'import':
                    imports.setdefault(_norm_sym_name(e['to_name'] or _hx(e['to'])), set()).add(_hx(e['site']))
                    continue
                h = e['func']
                if h is None or int(h.start) in seen:
                    continue
                if len(nodes) >= max_nodes:
                    cut = True
                    continue
                seen.add(int(h.start))
                nodes.append({'name': h.name, 'start': _hx(h.start), 'depth': d})
                nxt.append(h)
            if cut:
                break
        frontier = sorted(nxt, key=lambda x: int(x.start))
        if cut or not frontier:
            break
    return c.out({'function': _fref(root), 'nodes': nodes, 'edges': edges,
                  'imports': [{'name': k, 'sites': sorted(v)} for k, v in sorted(imports.items())],
                  'provenance': 'direct = resolved call instruction; tailcall = call site that is not a call '
                                'instruction (jump); import = imported/external target; unresolved-indirect = '
                                'call site without a resolved target (only direct edges are strong)'},
                 truncated=cut)


def call_paths(ops, bv, p):
    """Bounded, deterministic DFS for call paths src -> dst (dst may be a function or an import name)."""
    c = _Ctx(p, 60)
    src = resolve_function_strict(bv, c.req('src'))
    dst_raw = c.req('dst')
    max_hops = c.i('max_hops', 6, 1, 12)
    max_paths = c.i('max_paths', 20, 1, 500)
    dst_func = None
    dst_addrs = set()
    dst_names = set()
    try:
        dst_func = resolve_function_strict(bv, dst_raw)
        if _func_sym_type(dst_func) in _IMPORT_SYM_TYPES:
            dst_addrs.add(int(dst_func.start))
            dst_names |= _name_variants(dst_func.name)
    except rc.NotFoundError:
        rows = _symbol_addrs(bv, dst_raw)
        dst_addrs = {a for (a, _n, _k) in rows}
        dst_names = _name_variants(dst_raw)
        if not dst_addrs:
            raise rc.NotFoundError('destination function or import', dst_raw, None)
    cache = {}
    paths = []
    state = {'exp': 0, 'incomplete': False}
    dead = {}
    max_exp = 50000

    def is_hit(e):
        if dst_func is not None and e['func'] is not None and int(e['func'].start) == int(dst_func.start):
            return True
        if e['to'] is not None and e['to'] in dst_addrs:
            return True
        if dst_names and e['to_name'] and (_name_variants(e['to_name']) & dst_names):
            return True
        return False

    def dfs(fn, hops_left, on_stack, trail):
        found = False
        blocked = False
        for e in _edges(bv, fn, cache):
            if len(paths) >= max_paths or state['incomplete']:
                return found, True
            if e['prov'] == 'unresolved-indirect':
                continue
            hop = _edge_json(bv, fn, e)
            if is_hit(e):
                paths.append(trail + [hop])
                found = True
                continue
            g = e['func']
            if g is None or hops_left <= 1:
                continue
            gs = int(g.start)
            if gs in on_stack:
                blocked = True
                continue
            if dead.get(gs, 0) >= hops_left - 1:
                continue
            if c.expired() or state['exp'] >= max_exp:
                state['incomplete'] = True
                return found, True
            state['exp'] += 1
            f2, b2 = dfs(g, hops_left - 1, on_stack | {gs}, trail + [hop])
            found = found or f2
            blocked = blocked or b2
        if not found and not blocked:
            k = int(fn.start)
            dead[k] = max(dead.get(k, 0), hops_left)
        return found, blocked

    dfs(src, max_hops, {int(src.start)}, [])
    if state['incomplete']:
        c.warn('search budget exhausted (time-budget or %d expansions): the path list may be incomplete' % max_exp)
    cut = state['incomplete'] or len(paths) >= max_paths
    return c.out({'src': _fref(src), 'dst': _fref(dst_func) if dst_func is not None else dst_raw,
                  'paths': [{'length': len(pth), 'hops': pth} for pth in paths], 'expansions': state['exp'],
                  'complete': not cut,
                  'note': 'edges are static: indirect calls (vtables, function pointers, RPC dispatch) are not '
                          'followed; a path tier is strong only when every hop prov is direct'},
                 truncated=cut)


# ---------------------------------------------------------------------------------------------------------------
# verbs: return checks, sinks, gates
# ---------------------------------------------------------------------------------------------------------------

def _cmp_info(cond, tracked):
    """Describe an IF condition over a tracked SSA var: (op, const or None, text) or None if unrelated."""
    reads = {_svkey(sv) for _n, sv in _ssa_reads(cond)}
    if not (reads & tracked):
        return None
    opn = _op(cond)
    if opn in _CMP_OPS:
        consts = []
        for side in (getattr(cond, 'left', None), getattr(cond, 'right', None)):
            if side is not None and _op(side) in _CONST_OPS:
                consts.append(_const_val(side))
        return (opn, consts[0] if consts else None, _text(cond, 160))
    if opn in _SSA_VAR_READ_OPS:
        return ('TEST_NONZERO', 0, _text(cond, 160))
    if opn == 'MLIL_NOT':
        return ('TEST_ZERO', 0, _text(cond, 160))
    return (opn, None, _text(cond, 160))


def _trace_result(bv, f, ssa_il, outs, max_hops=4):
    tracked = {_svkey(sv) for sv in outs}
    work = collections.deque((sv, 0, None) for sv in outs)
    seen = set()
    checks, flows = [], []
    while work:
        sv, h, carried = work.popleft()
        k = _svkey(sv)
        if k in seen:
            continue
        seen.add(k)
        try:
            uses = list(ssa_il.get_ssa_var_uses(sv))
        except Exception:
            uses = []
        for u in uses:
            opn = _op(u)
            if opn == 'MLIL_IF':
                info = _cmp_info(u.condition, tracked)
                if info is not None and carried is not None and info[0] == 'TEST_NONZERO':
                    info = (carried[0], carried[1], carried[2] + ' (via ' + _text(u.condition, 60) + ')')
                tgt = {}
                for side in ('true', 'false'):
                    try:
                        t = _il_get(ssa_il, int(getattr(u, side)))
                        tgt[side] = _hx(_addr_of(t)) if t is not None else None
                    except Exception:
                        tgt[side] = None
                checks.append({'va': _hx(_addr_of(u)), 'sym': sym(bv, _addr_of(u), f), 'text': _text(u, 200),
                               'cmp': info[0] if info else None,
                               'const': _hx(info[1]) if (info and info[1] is not None) else None,
                               'branch_targets': tgt})
            elif opn in _SSA_SET_OPS:
                src = getattr(u, 'src', None)
                dest = getattr(u, 'dest', None)
                sop = _op(src) if src is not None else ''
                carry = None
                if sop in _CMP_OPS:
                    ci = _cmp_info(src, tracked)
                    carry = ci
                if dest is not None and hasattr(dest, 'version') and h < max_hops and (sop in _COPY_OPS or carry):
                    tracked.add(_svkey(dest))
                    work.append((dest, h + 1, carry))
                flows.append({'kind': 'assigned', 'va': _hx(_addr_of(u)), 'text': _text(u, 160)})
            elif opn == 'MLIL_VAR_PHI':
                dest = getattr(u, 'dest', None)
                if dest is not None and h < max_hops:
                    tracked.add(_svkey(dest))
                    work.append((dest, h + 1, carried))
            elif _is_call(u):
                a, nm = _callee_name(bv, u)
                flows.append({'kind': 'passed-to-call', 'callee': nm, 'va': _hx(_addr_of(u)), 'text': _text(u, 160)})
            elif opn.startswith('MLIL_RET'):
                flows.append({'kind': 'returned', 'va': _hx(_addr_of(u)), 'text': _text(u, 160)})
            elif opn in _STORE_SSA_OPS:
                flows.append({'kind': 'stored', 'va': _hx(_addr_of(u)), 'text': _text(u, 160)})
            else:
                flows.append({'kind': 'other', 'op': opn, 'va': _hx(_addr_of(u)), 'text': _text(u, 160)})
    return checks, flows


def _classify_checks(outs, checks, flows):
    if not outs:
        return 'none'
    if any(ch['const'] is not None for ch in checks):
        return 'compared-to-const'
    if checks:
        return 'compared-to-nonconst'
    if any(fl['kind'] in ('returned', 'passed-to-call', 'stored') for fl in flows):
        return 'passed-through'
    if flows:
        return 'used-unchecked'
    return 'none'


def return_check(ops, bv, p):
    """Is the result of the call at call_site checked, and how?"""
    c = _Ctx(p, 20)
    va = parse_va(bv, c.req('call_site'))
    f = _func_for_va(bv, va, c.s('function', ''))
    ssa_il = il_of(f, 'mlil', True, True)
    call = _call_at(bv, f, va, True)
    a, nm = _callee_name(bv, call)
    try:
        outs = [sv for sv in list(call.output) if hasattr(sv, 'version')]
    except Exception:
        outs = []
    out_exprs = []
    try:
        out_exprs = [_text(e, 120) for e in list(call.output_exprs)]
    except Exception:
        out_exprs = []
    checks, flows = _trace_result(bv, f, ssa_il, outs)
    verdict = _classify_checks(outs, checks, flows)
    canon = _norm_sym_name(nm) if nm else ''
    sem = _RETURN_SEMANTICS.get(canon) or _RETURN_SEMANTICS.get(canon.lstrip('_'))
    return c.out({
        'function': _fref(f), 'call_site': {'va': _hx(va), 'sym': sym(bv, va, f), 'text': _text(call)},
        'callee': nm, 'callee_va': _hx(a) if a is not None else None, 'outputs': [_svname(sv) for sv in outs],
        'output_exprs': out_exprs, 'checked': verdict, 'checks': checks[:100], 'flows': flows[:100],
        'constants': sorted({ch['const'] for ch in checks if ch['const'] is not None}),
        'api_semantics': ({'callee': canon, 'semantics': sem, 'source': 'documented API contract (MS Learn); '
                                                                        're-verify before citing'} if sem else None),
        'caveat': 'all comparisons are treated alike: the polarity of a check against the API '
                  'success semantics is NOT evaluated, and a check in a caller or after a copy through memory is '
                  'not seen; when outputs is empty the result was not captured in MLIL (discarded or unmodelled)',
    }, truncated=len(checks) > 100 or len(flows) > 100)


def _preset_names(c, key, default_presets):
    names = {}
    raw = [x.strip() for x in c.s(key, '').split(',') if x.strip()]
    presets = raw or list(default_presets)
    for pr in presets:
        pl = pr.lower()
        if pl == 'all':
            for k, v in SINK_PRESETS.items():
                for n in v:
                    names.setdefault(n, k)
            continue
        if pl not in SINK_PRESETS:
            raise _bad('unknown preset %r (known: %s, all)' % (pr, ', '.join(sorted(SINK_PRESETS))))
        for n in SINK_PRESETS[pl]:
            names.setdefault(n, pl)
    return names


def _intrinsic_hits(f, generate=False):
    hits = []
    try:
        il = getattr(f, 'mlil') if generate else (getattr(f, 'mlil_if_available')
                                                  if hasattr(f, 'mlil_if_available') else None)
    except Exception:
        il = None
    if il is None:
        return None
    try:
        for ins in il.instructions:
            if _op(ins) in _INTRINSIC_OPS:
                nm = str(getattr(ins, 'intrinsic', '') or '')
                if _INTRINSIC_SINK_RE.match(nm):
                    hits.append((_addr_of(ins), nm, ins))
    except Exception:
        pass
    return hits


def sinks(ops, bv, p):
    """Deterministic sink search by symbol cross-references (+ outlined builtins + memory intrinsics)."""
    c = _Ctx(p, 60)
    names = {}
    preset_given = bool(c.s('preset', '').strip())
    extra = [x.strip() for x in c.s('names', '').split(',') if x.strip()]
    if preset_given or not extra:
        names = _preset_names(c, 'preset', ('all',))
    for n in extra:
        names.setdefault(n, 'custom')
    inc_b = c.b('include_builtins', True)
    if inc_b:
        for n in _BUILTIN_SINKS:
            names.setdefault(n, 'builtin')
    offset = c.i('offset', 0, 0, 10 ** 7)
    limit = c.i('limit', 300, 1, 5000)
    per_sym = c.i('max_refs_per_symbol', 5000, 1, 100000)
    fn_param = c.s('function', '').strip()
    only = resolve_function_strict(bv, fn_param) if fn_param else None
    scan_intr = c.b('scan_intrinsics', only is not None) and inc_b
    rows = {}
    cut = False
    for nm in sorted(names):
        if c.expired():
            cut = True
            c.warn('time-budget: symbol scan stopped at %s' % nm)
            break
        addrs = {}
        for q in (nm, '__imp_' + nm):
            for (a, dn, kind) in _symbol_addrs(bv, q):
                addrs.setdefault(a, (dn, kind))
        for a in sorted(addrs):
            try:
                refs = list(bv.get_code_refs(a, max_items=per_sym + 1))
            except TypeError:
                refs = list(bv.get_code_refs(a))
            except Exception:
                refs = []
            if len(refs) > per_sym:
                cut = True
                c.warn('max_refs_per_symbol=%d reached for %s@%s' % (per_sym, nm, _hx(a)))
                refs = refs[:per_sym]
            for r in refs:
                fn = getattr(r, 'function', None)
                try:
                    site = int(r.address)
                except Exception:
                    continue
                if only is not None and (fn is None or int(fn.start) != int(only.start)):
                    continue
                k = (site, nm)
                if k in rows:
                    continue
                kind = addrs[a][1]
                rows[k] = {'sink': nm, 'preset': names[nm], 'va': _hx(site), 'sym': sym(bv, site, fn),
                           'function': _fref(fn) if fn is not None else None,
                           'call_insn': _is_call_insn(fn, site) if fn is not None else None,
                           'via': 'import' if kind in _IMPORT_SYM_TYPES else (
                               'builtin' if nm.startswith('__builtin_') else 'symbol'),
                           'target': _hx(a)}
    intr = None
    if scan_intr:
        funcs = [only] if only is not None else _sorted_functions(bv)
        done = 0
        skipped = 0
        for f in funcs:
            if c.expired():
                cut = True
                c.warn('time-budget: intrinsic scan stopped at %s@%s' % (f.name, _hx(f.start)))
                break
            hs = _intrinsic_hits(f, generate=only is not None)
            if hs is None:
                skipped += 1
                continue
            done += 1
            for (a, nm, _ins) in hs:
                if a is None:
                    continue
                rows.setdefault((a, nm), {'sink': nm, 'preset': 'intrinsic', 'va': _hx(a), 'sym': sym(bv, a, f),
                                          'function': _fref(f), 'call_insn': None, 'via': 'intrinsic',
                                          'target': None})
        intr = {'functions_scanned': done, 'functions_without_mlil': skipped, 'functions_total': len(funcs),
                'complete': done + skipped == len(funcs)}
    elif inc_b:
        c.warn('memory intrinsics (__memcpy_u*/__memfill_*) were not scanned for this whole-binary listing; '
               'pass function=<name> or scan_intrinsics=1')
    ordered = [rows[k] for k in sorted(rows, key=lambda k: (int(rows[k]['va'], 16), k[1]))]
    page = ordered[offset:offset + limit]
    more = len(ordered) > offset + limit
    return c.out({'sinks': page, 'total': len(ordered), 'names_queried': len(names), 'intrinsic_scan': intr,
                  'note': 'a sink site is a seed for bn_backward_slice / bn_possible_values, not a finding'},
                 truncated=more or cut, next_offset=(offset + limit) if more else None)


def _block_of(f, a):
    try:
        b = f.get_basic_block_at(a)
        if b is not None:
            return b
    except Exception:
        pass
    try:
        for b in f.basic_blocks:
            if int(b.start) <= a < int(b.end):
                return b
    except Exception:
        pass
    return None


def _dominates(blk_a, blk_b, va_a=None, va_b=None):
    """True if the instruction at va_a (in block a) dominates the instruction at va_b (in block b), same function;
    None if unknown. BN's BasicBlock.dominators includes the block itself and BN does not end blocks at calls, so
    when both sites share one block, dominance is decided by address order inside the block (straight-line code):
    a site dominates only a LATER site. A same-block pair without both addresses is unknown, never a guess."""
    if blk_a is None or blk_b is None:
        return None
    try:
        if int(blk_a.start) == int(blk_b.start):
            if va_a is None or va_b is None:
                return None
            return int(va_a) < int(va_b)
        starts = {int(x.start) for x in blk_b.dominators}
        return int(blk_a.start) in starts
    except Exception:
        return None


def undominated_sinks(ops, bv, p):
    """Sinks in one function that are NOT dominated by a gate call (impersonation / access decision)."""
    c = _Ctx(p, 60)
    f = resolve_function_strict(bv, c.req('function'))
    gates = set()
    graw = [x.strip() for x in c.s('gate', '').split(',') if x.strip()]
    for g in (graw or list(_DEFAULT_GATES)):
        gates |= _name_variants(g)
    sink_names = _preset_names(c, 'preset', _DEFAULT_UNDOMINATED_PRESETS)
    sink_set = {}
    for n, pr in sink_names.items():
        for v in _name_variants(n):
            if v not in gates:
                sink_set.setdefault(v, (n, pr))
    for n in _BUILTIN_SINKS:
        sink_set.setdefault(n, (n, 'builtin'))
    cache = {}
    gate_sites = []
    sink_sites = []
    for e in _edges(bv, f, cache):
        vs = _name_variants(e['to_name']) if e['to_name'] else set()
        if vs & gates:
            gate_sites.append((e['site'], e['to_name']))
        hit = [sink_set[v] for v in sorted(vs) if v in sink_set]
        if hit:
            sink_sites.append((e['site'], hit[0][0], hit[0][1]))
    for (a, nm, _ins) in (_intrinsic_hits(f, generate=True) or []):
        if a is not None:
            sink_sites.append((a, nm, 'intrinsic'))
    gate_sites = sorted(set(gate_sites))
    sink_sites = sorted(set(sink_sites))
    ssa_il = None
    try:
        ssa_il = il_of(f, 'mlil', True, True)
    except rc.ApiError:
        c.warn('no MLIL-SSA: gate result checks were not evaluated')
    gate_rows = []
    for (ga, gname) in gate_sites:
        gb = _block_of(f, ga)
        check_blocks = []
        checked = None
        if ssa_il is not None:
            try:
                call = _call_at(bv, f, ga, True)
                outs = [sv for sv in list(call.output) if hasattr(sv, 'version')]
                checks, flows = _trace_result(bv, f, ssa_il, outs)
                checked = _classify_checks(outs, checks, flows)
                for ch in checks:
                    if ch.get('va'):
                        cva = int(ch['va'], 16)
                        cb = _block_of(f, cva)
                        if cb is not None:
                            check_blocks.append((cb, cva))
            except Exception:
                checked = None
        gate_rows.append({'site': ga, 'name': gname, 'block': gb, 'checked': checked, 'check_blocks': check_blocks})
    rows = []
    for (sa, sname, preset) in sink_sites:
        sb = _block_of(f, sa)
        dom_by = []
        unknown = False
        chk = False
        for g in gate_rows:
            if g['site'] == sa:
                continue
            d = _dominates(g['block'], sb, g['site'], sa)
            if d is None:
                unknown = True
            elif d:
                dom_by.append({'gate': g['name'], 'va': _hx(g['site']), 'result_checked': g['checked']})
                for (cb, cva) in g['check_blocks']:
                    if _dominates(cb, sb, cva, sa):
                        chk = True
        rows.append({'sink': sname, 'preset': preset, 'va': _hx(sa), 'sym': sym(bv, sa, f),
                     'dominated_by_gate_call': bool(dom_by) if not (unknown and not dom_by) else None,
                     'dominating_gates': dom_by, 'gate_check_dominates': chk if dom_by else False})
    cap = 2000
    und = [r for r in rows if r['dominated_by_gate_call'] is not True]
    return c.out({
        'function': _fref(f),
        'gates': [{'name': g['name'], 'va': _hx(g['site']), 'sym': sym(bv, g['site'], f),
                   'result_checked': g['checked']} for g in gate_rows][:cap],
        'sinks': rows[:cap], 'undominated': und[:cap], 'sink_count': len(rows), 'undominated_count': len(und),
        'caveat': 'intra-procedural dominance at disassembly-block level (a gate in the sink\'s own block dominates '
                  'it only when it comes first by address): a gate in a caller is invisible, the '
                  'branch polarity of a gate check is not evaluated, and gate_check_dominates only says an IF on '
                  'the gate result dominates the sink. Each undominated sink is a hypothesis ranked by sink power '
                  '(pre-gate side effects), never a finding',
    }, truncated=len(rows) > cap or len(gate_rows) > cap)


# ---------------------------------------------------------------------------------------------------------------
# verbs: frame, uninitialized reads
# ---------------------------------------------------------------------------------------------------------------

def stack_frame(ops, bv, p):
    c = _Ctx(p, 20)
    f = resolve_function_strict(bv, c.req('function'))
    items = []
    try:
        layout = list(f.stack_layout)
    except Exception as e:
        raise _api('UNSUPPORTED_API', 'stack_layout unavailable: %s' % _clip(e, 160), 501)
    for v in layout:
        try:
            off = int(v.storage)
        except Exception:
            continue
        t = getattr(v, 'type', None)
        w = None
        try:
            w = int(t.width) if t is not None else None
        except Exception:
            w = None
        items.append({'name': getattr(v, 'name', '?'), 'offset': _hx(off), 'offset_int': off, 'size': w,
                      'type': _clip(t, 200) if t is not None else None, 'storage_kind': _var_storage_kind(v)})
    items.sort(key=lambda r: (r['offset_int'], r['name']))
    for i in range(len(items) - 1):
        a, b = items[i], items[i + 1]
        if a['size'] and a['offset_int'] + a['size'] > b['offset_int']:
            a['overlaps_next'] = b['name']
    params = []
    try:
        for i, v in enumerate(f.parameter_vars):
            params.append({'index': i, 'name': v.name, 'type': _clip(getattr(v, 'type', None), 200),
                           'storage_kind': _var_storage_kind(v), 'storage': _hx(getattr(v, 'storage', 0))})
    except Exception:
        pass
    cut = len(items) > 2000
    return c.out({'function': _fref(f), 'stack_vars': items[:2000], 'parameters': params,
                  'note': 'offsets are BN stack offsets (negative = below the return address); overlapping slots '
                          'and unnamed gaps deserve a look for overflow / uninitialized-use classes'}, truncated=cut)


def uninit_reads(ops, bv, p):
    """Reads of an SSA version 0 that is not a parameter (HYPOTHESIS until checked at run time)."""
    c = _Ctx(p, 30)
    f = resolve_function_strict(bv, c.req('function'))
    ssa_il = il_of(f, 'mlil', True, True)
    pkeys = _param_keys(f)
    hits = []
    seen = set()
    cut = False
    cap = c.i('limit', 500, 1, 5000)

    def consider(sv, ins, kind):
        if int(getattr(sv, 'version', -1)) != 0:
            return
        if _vkey(sv.var) in pkeys:
            return
        k = (_svkey(sv), getattr(ins, 'instr_index', None), kind)
        if k in seen:
            return
        seen.add(k)
        hits.append({'status': 'HYPOTHESIS', 'kind': kind, 'var': _svname(sv),
                     'storage_kind': _var_storage_kind(sv.var), 'va': _hx(_addr_of(ins)),
                     'sym': sym(bv, _addr_of(ins), f) if _addr_of(ins) is not None else None,
                     'text': _text(ins, 200)})

    try:
        for ins in ssa_il.instructions:
            if c.expired():
                cut = True
                c.warn('time-budget')
                break
            if len(hits) >= cap:
                cut = True
                break
            if _op(ins) == 'MLIL_VAR_PHI':
                for sv in (getattr(ins, 'src', None) or []):
                    consider(sv, ins, 'phi-path')
                continue
            for node in ins.traverse(lambda n: n if _op(n) in ('MLIL_VAR_SSA', 'MLIL_VAR_SSA_FIELD') else None):
                sv = getattr(node, 'src', None)
                if sv is not None and hasattr(sv, 'version'):
                    consider(sv, ins, 'read')
    except Exception as e:
        c.warn('IL walk failed: %s' % _clip(e, 160))
    hits.sort(key=lambda h: (h['storage_kind'] != 'stack', int(h['va'], 16) if h['va'] else 0, h['var']))
    return c.out({'function': _fref(f), 'label': 'HYPOTHESIS', 'hits': hits[:cap],
                  'blind_spots': ['aliased (address-taken) variables are memory-backed and excluded',
                                  'register version-0 reads include callee-saved registers and calling-convention '
                                  'artifacts; stack version-0 reads are the stronger signal',
                                  'initialization through a pointer in a callee is not modelled'],
                  'next_step': 'confirm at run time (for example with a marker value) before any claim'},
                 truncated=cut)


# ---------------------------------------------------------------------------------------------------------------
# verbs: handler slice (context pack)
# ---------------------------------------------------------------------------------------------------------------

_TYPE_KEYWORDS = frozenset({
    'struct', 'union', 'enum', 'class', 'const', 'volatile', 'unsigned', 'signed', 'int', 'char', 'short', 'long',
    'void', 'float', 'double', 'bool', '__ptr64', '__ptr32', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'wchar16', 'wchar32', 'char16_t', 'char32_t', 'wchar_t',
    '__stdcall', '__cdecl', '__fastcall', '__thiscall', 'noreturn', '__noreturn', '__pure', 'size_t',
})


def _type_names_of(f):
    texts = []
    try:
        texts.append(str(f.type))
    except Exception:
        pass
    try:
        for v in f.vars:
            t = getattr(v, 'type', None)
            if t is not None:
                texts.append(str(t))
    except Exception:
        pass
    names = set()
    for t in texts:
        for m in re.finditer(r'[A-Za-z_][A-Za-z0-9_:]*', t):
            w = m.group(0)
            if w not in _TYPE_KEYWORDS and not re.match(r'^u?int\d+_t$', w):
                names.add(w)
    return names


def _render_type(bv, name):
    try:
        t = bv.get_type_by_name(name)
    except Exception:
        t = None
    if t is None:
        return None
    members = None
    try:
        members = list(getattr(t, 'members'))
    except Exception:
        members = None
    lines = []
    if members:
        first = members[0]
        if hasattr(first, 'offset'):
            w = getattr(t, 'width', None)
            lines.append('struct %s  // width %s' % (name, _hx(w) if isinstance(w, int) else '?'))
            for m in members[:64]:
                lines.append('  +%s  %s %s;' % (_hx(getattr(m, 'offset', 0)), _clip(getattr(m, 'type', '?'), 120),
                                                getattr(m, 'name', '?')))
            if len(members) > 64:
                lines.append('  // ... %d more member(s)' % (len(members) - 64))
        else:
            lines.append('enum %s' % name)
            for m in members[:64]:
                lines.append('  %s = %s' % (getattr(m, 'name', '?'), _hx(getattr(m, 'value', 0))))
            if len(members) > 64:
                lines.append('  // ... %d more member(s)' % (len(members) - 64))
    else:
        lines.append('typedef %s %s;' % (_clip(t, 300), name))
    return lines


def _strings_of(bv, f, ranges=None):
    """{address: value} of the strings f's MLIL points at. When `ranges` (a dict) is given, it also records each
    string's byte extent as ranges[address] = (start, start + length), or None when the length is unknown: the value
    is read from the CURRENT bytes, so a pack must count modifications over these extents too."""
    out = {}
    try:
        il = getattr(f, 'mlil')
    except Exception:
        il = None
    if il is None:
        return out
    try:
        for ins in il.instructions:
            for node in ins.traverse(lambda n: n if _op(n) in ('MLIL_CONST_PTR', 'MLIL_CONST') else None):
                a = _const_val(node)
                if a is None or a in out or a < 0:
                    continue
                try:
                    s = bv.get_string_at(a)
                except Exception:
                    s = None
                if s is None:
                    continue
                try:
                    if int(s.start) != a:
                        continue
                    out[a] = str(s.value)
                except Exception:
                    continue
                if ranges is not None:
                    try:
                        n = int(getattr(s, 'length'))
                        ranges[a] = (a, a + n) if n >= 0 else None
                    except Exception:
                        ranges[a] = None
    except Exception:
        pass
    return out


def _recorded_view_modifications(ops, bv, info):
    """What the SERVER recorded about modifications of `bv`, independent of which bytes a pack renders:
    (notes, record). A note means `bv` may not show the bytes of the file on disk, so a pack of it fails closed:
      * patch_bytes writes recorded on the view this session (the `_binary` echo's `modified`), anywhere in the
        image: callee bytes the pack does not render (beyond depth / max_callees, or dropped by max_chars), jump
        tables and read-only data all shape the rendered HLIL, so the in-slice count alone cannot clear the view;
      * a record that cannot be read (fail closed).
    record = {'raw_patch_count': int | None, 'raw_patch_bytes': int | None}. Never raises. In-memory edits the
    server never saw (for example made in the Binary Ninja UI) are not recorded."""
    notes = []
    rec = {'raw_patch_count': 0, 'raw_patch_bytes': 0}
    info = info if isinstance(info, dict) else {}
    vid = str(info.get('view_id') or '')
    vid_known = bool(vid)
    if not vid:
        try:
            d = ops.describe_view(bv, 'explicit')
            vid = str((d or {}).get('view_id') or '') if isinstance(d, dict) else ''
            vid_known = isinstance(d, dict)      # '' = an unregistered view (no record can exist for it)
        except Exception:
            vid_known = False
    f = getattr(ops, 'raw_patches', None)
    if not callable(f):
        # no record accessor: only an explicit modified=false in the echo clears the view
        rec['raw_patch_count'] = rec['raw_patch_bytes'] = None
        sm = info.get('modified')
        if sm is not False:
            notes.append('MODIFIED: %s' % ('raw patch(es) are recorded on this view (modified)' if sm else
                                           'this server keeps no raw-patch record, so the view cannot be shown '
                                           'unpatched'))
        return notes, rec
    if not vid_known:
        rec['raw_patch_count'] = rec['raw_patch_bytes'] = None
        notes.append('MODIFIED: the view id is unknown, so its raw-patch record cannot be read')
        return notes, rec
    try:
        # an unregistered view has no id and no record: patch_bytes registers the view it writes
        raw = list(f(vid) or []) if vid else []
    except Exception as e:
        rec['raw_patch_count'] = rec['raw_patch_bytes'] = None
        notes.append('MODIFIED: the raw-patch record of this view could not be read (%s)' % _clip(e, 120))
        return notes, rec
    nbytes = 0
    for x in raw:
        try:
            nbytes += max(0, int((x or {}).get('len') or 0))
        except Exception:
            pass
    rec['raw_patch_count'], rec['raw_patch_bytes'] = len(raw), nbytes
    if raw:
        notes.append('MODIFIED: %d raw patch(es) (%d byte(s)) recorded on this view by patch_bytes (modified); '
                     'the pack may not show the bytes of the file on disk' % (len(raw), nbytes))
    return notes, rec


def handler_slice(ops, bv, p):
    """Deterministic context pack: the handler + callees to a fixed depth (BFS sorted by address), callers,
    imports, types, strings and optionally the target's disassembly. Same inputs -> same pack_sha256.
    modified_bytes_in_slice counts the patched bytes the pack renders (the functions it renders and the extents of
    the strings they reference). It is None, never 0, when that count is unknown OR when the server recorded a
    modification of the view itself (a patch_bytes write anywhere in the image); those cases are also listed first
    in sections_missing, so the pack is incomplete (fail closed)."""
    c = _Ctx(p, 120)
    f = resolve_function_strict(bv, c.req('function'))
    depth = c.i('depth', 3, 0, 4)
    max_callees = c.i('max_callees', 40, 0, 400)
    max_chars = c.i('max_chars', 120000, 4000, 1800000)
    disasm = c.b('disasm', False)
    inc = [x.strip().lower() for x in c.s('include', 'hlil,callers,types,strings,imports').split(',') if x.strip()]
    allowed = ('hlil', 'callers', 'types', 'strings', 'imports')
    bad = [x for x in inc if x not in allowed]
    if bad:
        raise _bad('include tokens must be from %s (got %s)' % (','.join(allowed), ','.join(bad)))
    inc = set(inc)
    cache = {}
    missing = []
    no_il = False
    renders = set()
    # The analysis state is sampled at the start, after callee discovery, when the header is built and at the
    # very end. A pack whose callees/HLIL were read while analysis was not IdleState is not reproducible, so any
    # non-IdleState sample makes it incomplete (the HTTP echo re-reads the state only at response time).
    states_seen = [_view_state(ops, bv)]
    state0 = states_seen[0]

    # 1. deterministic BFS over resolved direct/tailcall callees, by level, each level sorted by start
    included = []
    seen = {int(f.start)}
    discovered_not_included = set()
    frontier = [f]
    for d in range(1, depth + 1):
        nxt = []
        for g in frontier:
            for e in _edges(bv, g, cache):
                if e['prov'] == 'import':
                    continue
                h = e['func']
                if h is None:
                    continue
                hs = int(h.start)
                if hs in seen:
                    continue
                seen.add(hs)
                nxt.append(h)
        nxt.sort(key=lambda x: int(x.start))
        level_kept = []
        for h in nxt:
            if len(included) < max_callees:
                included.append((h, d))
                level_kept.append(h)
            else:
                discovered_not_included.add(int(h.start))
        frontier = level_kept
        if not frontier:
            break
    if c.expired():
        c.warn('time-budget: callee discovery exceeded the budget')
    states_seen.append(_view_state(ops, bv))

    # 2. sections
    info = _info_for(ops, bv)
    sections = []

    def hlil_section(fn, title, depth_label):
        try:
            lines, used = render_function_lines(bv, fn, 'hlil', False, 'ast', True)
            renders.add(used)
        except rc.ApiError as e:
            return None, getattr(e, 'code', 'NO_IL')
        body = ['// %s @ %s%s' % (sym(bv, fn.start, fn), _hx(fn.start), depth_label)]
        body.extend(_fmt_line(a, t) for (a, t) in lines)
        return {'name': title, 'lines': body, 'kind': 'target' if not depth_label else 'callee'}, None

    tsec, terr = hlil_section(f, 'TARGET HLIL (%s)' % f.name, '')
    if tsec is None:
        missing.append('TARGET HLIL (%s): %s' % (f.name, terr))
        no_il = True
    else:
        sections.append(tsec)
    if 'hlil' in inc:
        for (h, d) in included:
            if c.expired():
                missing.append('CALLEE HLIL (%s @ %s): time-budget' % (h.name, _hx(h.start)))
                continue
            s, err = hlil_section(h, 'CALLEE HLIL (%s @ %s)' % (h.name, _hx(h.start)), ', depth %d' % d)
            if s is None:
                missing.append('CALLEE HLIL (%s @ %s): %s' % (h.name, _hx(h.start), err))
                no_il = True
            else:
                sections.append(s)
    if 'callers' in inc:
        cl = _callers_of(bv, f)
        body = ['%s  %s  %s  (%s)' % (_hx(site), sym(bv, site, cf), _hx(cf.start), prov) for (cf, site, prov) in cl[:50]]
        if len(cl) > 50:
            body.append('// ... %d more caller site(s)' % (len(cl) - 50))
        if not body:
            body = ['// no direct callers (indirect dispatch, exports or vtables are not call edges)']
        sections.append({'name': 'CALLERS', 'lines': body, 'kind': 'optional'})
    if 'imports' in inc:
        imports = {}
        for fn in [f] + [h for (h, _d) in included]:
            for e in _edges(bv, fn, cache):
                if e['prov'] == 'import':
                    imports.setdefault(_norm_sym_name(e['to_name'] or _hx(e['to'])), set()).add(e['site'])
        body = []
        for k in sorted(imports):
            body.append('%s  at %s' % (k, ', '.join(_hx(s) for s in sorted(imports[k])[:16])))
        sections.append({'name': 'IMPORTS', 'lines': body or ['// none'], 'kind': 'optional'})
    if 'types' in inc:
        names = set()
        for fn in [f] + [h for (h, _d) in included]:
            names |= _type_names_of(fn)
        body = []
        looked = 0
        rendered = 0
        for n in sorted(names):
            if looked >= 200 or rendered >= 40:
                break
            looked += 1
            tl = _render_type(bv, n)
            if tl:
                body.extend(tl)
                rendered += 1
        sections.append({'name': 'TYPES', 'lines': body or ['// no named types resolved'], 'kind': 'optional'})
    # Strings are read from the CURRENT bytes (the STRINGS section, and HLIL renders string literals inline), so
    # their extents are collected even without the STRINGS section and counted in modified_bytes_in_slice below.
    allstr = {}
    str_ranges = {}
    for fn in [f] + [h for (h, _d) in included]:
        for a, s in _strings_of(bv, fn, str_ranges).items():
            allstr.setdefault(a, s)
    if 'strings' in inc:
        body =['%s  %s' % (_hx(a), json.dumps(_clip(allstr[a], 200), ensure_ascii=False))
                for a in sorted(allstr)[:200]]
        if len(allstr) > 200:
            body.append('// ... %d more string(s)' % (len(allstr) - 200))
        sections.append({'name': 'STRINGS', 'lines': body or ['// none'], 'kind': 'optional'})
    if disasm:
        al = _asm_lines(bv, f)
        body = [_fmt_line(a, t) for (a, t) in al[:_SECTION_DISASM_MAX_LINES]]
        if len(al) > _SECTION_DISASM_MAX_LINES:
            body.append('## DISASSEMBLY TRUNCATED')
        if not al:
            missing.append('DISASSEMBLY (%s): no instructions decoded' % f.name)
        sections.append({'name': 'DISASSEMBLY (%s)' % f.name, 'lines': body, 'kind': 'disasm'})

    state = _view_state(ops, bv)
    states_seen.append(state)
    render_used = (sorted(renders)[0] if len(renders) == 1 else ('mixed:' + '+'.join(sorted(renders))
                                                                 if renders else 'none'))

    def assemble(secs):
        hdr = [
            '# BN-PACK v1',
            'binary_id: %s' % (info.get('binary_id') or 'unavailable'),
            'sha256: %s' % (info.get('sha256') or 'unavailable'),
            'basename: %s' % (info.get('basename') or _basename(bv)),
            'function: %s@%s' % (sym(bv, f.start, f), _hx(f.start)),
            'depth: %d' % depth,
            'analysis_state: %s' % state,
            'render_used: %s' % render_used,
            'sections: %s' % ' | '.join(s['name'] for s in secs),
        ]
        parts = ['\n'.join(hdr)]
        for s in secs:
            parts.append('## %s\n%s' % (s['name'], '\n'.join(s['lines'])))
        return '\n\n'.join(parts) + '\n'

    # 3. size control, deterministic: drop callees from the end, then optional sections, then cut the
    #    disassembly, then cut the target (the last one makes the pack incomplete)
    dropped = []
    truncated = False
    text = assemble(sections)
    while len(text) > max_chars:
        cal = [i for i, s in enumerate(sections) if s['kind'] == 'callee']
        if cal:
            s = sections.pop(cal[-1])
            dropped.append(s['name'])
            truncated = True
            text = assemble(sections)
            continue
        opt = [i for i, s in enumerate(sections) if s['kind'] == 'optional']
        if opt:
            order = ['STRINGS', 'TYPES', 'CALLERS', 'IMPORTS']
            opt.sort(key=lambda i: order.index(sections[i]['name']) if sections[i]['name'] in order else 9)
            s = sections.pop(opt[0])
            dropped.append(s['name'])
            truncated = True
            text = assemble(sections)
            continue
        cut_done = False
        for kind, marker in (('disasm', '## DISASSEMBLY TRUNCATED'), ('target', '// TARGET HLIL TRUNCATED')):
            idx = [i for i, s in enumerate(sections) if s['kind'] == kind]
            if not idx:
                continue
            s = sections[idx[0]]
            over = len(text) - max_chars
            keep = list(s['lines'])
            if keep and keep[-1] == marker:
                keep.pop()
            removed = 0
            while keep and removed < over + len(marker) + 2:
                removed += len(keep.pop()) + 1
            if not keep:
                continue
            s['lines'] = keep + [marker]
            truncated = True
            tmsg = 'TARGET HLIL (%s): truncated by max_chars=%d' % (f.name, max_chars)
            if kind == 'target' and tmsg not in missing:
                missing.append(tmsg)
            text = assemble(sections)
            cut_done = True
            break
        if not cut_done:
            break
    if len(text) > max_chars:
        missing.append('PACK: could not fit max_chars=%d' % max_chars)
        truncated = True
    callees_omitted = len(discovered_not_included) + sum(1 for n in dropped if n.startswith('CALLEE HLIL'))
    kept_callee_funcs = [h for (h, _d) in included
                         if any(s['name'] == 'CALLEE HLIL (%s @ %s)' % (h.name, _hx(h.start)) for s in sections)]
    mod = modified_bytes(bv, [f] + kept_callee_funcs, [str_ranges[a] for a in sorted(str_ranges)])
    # A modification the server recorded anywhere in the view (a patch_bytes write outside the rendered ranges)
    # can shape the rendered HLIL, so the in-slice count cannot clear it: fail closed (mod None, never 0, and the
    # pack is incomplete).
    taint_notes, recorded = _recorded_view_modifications(ops, bv, info)
    if taint_notes:
        mod = None
    head = []
    states_seen.append(_view_state(ops, bv))
    if any(s != 'IdleState' for s in states_seen):
        head.append('ANALYSIS: state was %s at start, %s at end (observed %s); the pack was rendered from '
                    'unfinished analysis' % (state0, states_seen[-1], ' > '.join(states_seen)))
    head.extend(taint_notes)
    # first, so a client that clips sections_missing still shows why
    missing[0:0] = head
    pack_sha = hashlib.sha256(text.encode('utf-8')).hexdigest()
    complete = (not missing) and (not no_il)
    return c.out({
        'pack_text': text, 'pack_sha256': pack_sha, 'function': _fref(f), 'sections': [s['name'] for s in sections],
        'sections_missing': missing, 'sections_dropped': dropped, 'complete': complete,
        'modified_bytes_in_slice': mod, 'callees_included': len(kept_callee_funcs), 'callees_omitted': callees_omitted,
        'truncated': truncated, 'render_used': render_used, 'analysis_state': state, 'chars': len(text),
        'analysis_state_at_start': state0, 'analysis_state_at_end': states_seen[-1],
        'recorded_modifications': recorded,
    }, truncated=truncated)


# ---------------------------------------------------------------------------------------------------------------
# verbs: entities, bytes, xrefs, debug info
# ---------------------------------------------------------------------------------------------------------------

def resolve_entity(ops, bv, p):
    """Resolve a cited entity (symbol, sym+off, module!sym+off, 0x address) to a canonical record."""
    c = _Ctx(p, 15)
    ref = c.req('ref')
    try:
        va = parse_va(bv, ref)
    except rc.NotFoundError:
        f = resolve_function_strict(bv, ref)
        va = int(f.start)
    rec = {'ref': ref, 'va': _hx(va), 'sym': sym(bv, va)}
    fa = _func_at(bv, va)
    fs = _containing(bv, va)
    s = _sym_at(bv, va)
    kind = 'address'
    if fa is not None:
        kind = 'function'
        rec['function'] = _fref(fa)
        rec['symbol_type'] = _func_sym_type(fa)
    elif fs:
        kind = 'code'
        rec['containing_functions'] = [_fref(x) for x in fs]
    if s is not None:
        rec['symbol'] = {'name': getattr(s, 'name', None), 'full_name': getattr(s, 'full_name', None),
                         'raw_name': getattr(s, 'raw_name', None), 'type': _sym_type_name(s)}
        if kind == 'address':
            kind = 'import' if _sym_type_name(s) in _IMPORT_SYM_TYPES else 'data'
    try:
        st = bv.get_string_at(va)
        if st is not None and int(st.start) == va:
            rec['string'] = _clip(st.value, 200)
            if kind in ('address', 'data'):
                kind = 'string'
    except Exception:
        pass
    try:
        rec['valid'] = bool(bv.is_valid_offset(va))
    except Exception:
        rec['valid'] = None
    try:
        b = bv.read(va, 16) or b''
        rec['bytes_hex'] = bytes(b).hex()
    except Exception:
        rec['bytes_hex'] = None
    rec['sections'] = _section_names(bv, va)
    rec['kind'] = kind
    return c.out(rec)


def bytes_at(ops, bv, p):
    c = _Ctx(p, 10)
    va = parse_va(bv, c.req('va'))
    n = c.i('length', 16, 1, 256)
    try:
        data = bytes(bv.read(va, n) or b'')
    except Exception as e:
        raise rc.NotFoundError('readable bytes at', _hx(va), [_clip(e, 120)])
    if not data:
        raise rc.NotFoundError('readable bytes at', _hx(va), None)
    return c.out({'va': _hx(va), 'sym': sym(bv, va), 'length': len(data), 'requested': n, 'hex': data.hex(),
                  'modification': _mod_summary(bv, va, len(data)), 'sections': _section_names(bv, va)},
                 truncated=len(data) < n)


def xrefs(ops, bv, p):
    c = _Ctx(p, 30)
    va = parse_va(bv, c.req('va'))
    kind = c.s('kind', 'code').strip().lower() or 'code'
    if kind not in ('code', 'data', 'both'):
        raise _bad('kind must be code, data or both')
    offset = c.i('offset', 0, 0, 10 ** 7)
    limit = c.i('limit', 500, 1, 5000)
    max_items = offset + limit + 1
    items = []
    if kind in ('code', 'both'):
        try:
            refs = list(bv.get_code_refs(va, max_items=max_items))
        except TypeError:
            refs = list(bv.get_code_refs(va))[:max_items]
        for r in refs:
            fn = getattr(r, 'function', None)
            try:
                a = int(r.address)
            except Exception:
                continue
            items.append({'kind': 'code', 'va': _hx(a), 'sym': sym(bv, a, fn),
                          'function': _fref(fn) if fn is not None else None})
    if kind in ('data', 'both') and len(items) < max_items:
        try:
            drefs = list(bv.get_data_refs(va, max_items=max_items))
        except TypeError:
            drefs = list(bv.get_data_refs(va))[:max_items]
        for a in drefs:
            items.append({'kind': 'data', 'va': _hx(a), 'sym': sym(bv, int(a))})
    page = items[offset:offset + limit]
    more = len(items) > offset + limit
    return c.out({'target': _hx(va), 'target_sym': sym(bv, va), 'kind': kind, 'xrefs': page,
                  'order': 'core order (stable for an unchanged database); pages are slices of that order'},
                 truncated=more, next_offset=(offset + limit) if more else None)


def _u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def _u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def _codeview_from(view, base, mapped, raw_view=None):
    hdr = view.read(base, 0x40) or b''
    if len(hdr) < 0x40 or hdr[:2] != b'MZ':
        return None
    lfanew = _u32(hdr, 0x3c)
    pe = view.read(base + lfanew, 24) or b''
    if len(pe) < 24 or pe[:4] != b'PE\x00\x00':
        return None
    nsec = _u16(pe, 6)
    optsz = _u16(pe, 20)
    opt = view.read(base + lfanew + 24, optsz) or b''
    if len(opt) < 2:
        return None
    magic = _u16(opt, 0)
    if magic == 0x20b:
        dd = 112
    elif magic == 0x10b:
        dd = 96
    else:
        return None
    if len(opt) < dd:
        return None
    nrva = _u32(opt, dd - 4)
    if nrva <= 6 or len(opt) < dd + 7 * 8:
        return {'found': False, 'reason': 'no debug data directory'}
    drva, dsize = _u32(opt, dd + 48), _u32(opt, dd + 52)
    if not drva or not dsize:
        return {'found': False, 'reason': 'empty debug data directory'}
    secs = []
    sh = view.read(base + lfanew + 24 + optsz, 40 * min(nsec, 96)) or b''
    for i in range(min(nsec, 96)):
        if len(sh) < (i + 1) * 40:
            break
        secs.append((_u32(sh, i * 40 + 12), _u32(sh, i * 40 + 8), _u32(sh, i * 40 + 16), _u32(sh, i * 40 + 20)))

    def rva_off(rva):
        for (va_, vs, rs, pr) in secs:
            if va_ <= rva < va_ + max(vs, rs):
                return pr + (rva - va_)
        return None
    if mapped:
        ddata = view.read(base + drva, min(dsize, 28 * 32)) or b''
    else:
        o = rva_off(drva)
        ddata = (view.read(base + o, min(dsize, 28 * 32)) or b'') if o is not None else b''
    for i in range(len(ddata) // 28):
        e = ddata[i * 28:(i + 1) * 28]
        if _u32(e, 12) != 2:
            continue
        size, arva, ptr = _u32(e, 16), _u32(e, 20), _u32(e, 24)
        n = min(size, 1024)
        data = b''
        if mapped and arva:
            data = view.read(base + arva, n) or b''
        if not data[:4] == b'RSDS' and raw_view is not None and ptr:
            data = raw_view.read(ptr, n) or b''
        if not mapped and not data and ptr:
            data = view.read(base + ptr, n) or b''
        if len(data) >= 24 and data[:4] == b'RSDS':
            d1, d2, d3 = struct.unpack_from('<IHH', data, 4)
            d4 = data[12:20]
            age = _u32(data, 20)
            path = data[24:].split(b'\x00', 1)[0].decode('utf-8', 'replace')
            guid = '{%08X-%04X-%04X-%s-%s}' % (d1, d2, d3, d4[:2].hex().upper(), d4[2:].hex().upper())
            return {'found': True, 'format': 'RSDS', 'guid': guid, 'age': age,
                    'symsrv_key': '%08X%04X%04X%s%X' % (d1, d2, d3, d4.hex().upper(), age),
                    'pdb_path': _clip(path, 260), 'source': 'mapped' if mapped else 'raw'}
    return {'found': False, 'reason': 'no CodeView RSDS entry in the debug directory'}


def _pe_codeview(bv):
    raw = None
    try:
        raw = bv.parent_view
    except Exception:
        raw = None
    bases = []
    for b in (getattr(bv, 'image_base', None), getattr(bv, 'start', None)):
        try:
            if b is not None and int(b) not in bases:
                bases.append(int(b))
        except Exception:
            pass
    for b in bases:
        try:
            r = _codeview_from(bv, b, True, raw)
            if r is not None:
                return r
        except Exception:
            continue
    if raw is not None:
        try:
            r = _codeview_from(raw, 0, False)
            if r is not None:
                return r
        except Exception:
            pass
    return {'found': False, 'reason': 'not a PE image or headers not readable'}


def _metadata_keys(bv):
    try:
        from binaryninja import metadata as _md
        from binaryninja import _binaryninjacore as _core
        h = _core.BNBinaryViewGetMetadata(bv.handle)
        if h is not None:
            return sorted(str(k) for k in _md.Metadata(handle=h))
    except Exception:
        pass
    try:
        return sorted(str(k) for k in bv.metadata.keys())
    except Exception:
        return None


def debug_info_status(ops, bv, p):
    """Which debug info is present and which PDB the IMAGE asks for (CodeView RSDS GUID/age)."""
    c = _Ctx(p, 30)
    cv = _pe_codeview(bv)
    try:
        parsers = sorted(set(bv.debug_info.parsers))
    except Exception:
        parsers = None
    keys = _metadata_keys(bv)
    md = None
    if keys is not None:
        md = [k for k in keys if re.search(r'pdb|debug|symbol', k, re.IGNORECASE)][:50]
    total = 0
    named = 0
    cut = False
    try:
        for f in bv.functions:
            if c.expired():
                cut = True
                c.warn('time-budget: named_ratio computed over a prefix')
                break
            total += 1
            if not _AUTO_NAME_RE.match(f.name):
                named += 1
    except Exception:
        pass
    ratio = (float(named) / total) if total else None
    pdb_parser = any('pdb' in x.lower() for x in (parsers or []))
    if pdb_parser:
        verdict = 'pdb-debug-info-present'
    elif ratio is not None and ratio >= 0.5:
        verdict = 'names-present-no-debug-parser-recorded'
    else:
        verdict = 'no-symbols'
    return c.out({
        'codeview': cv, 'debug_parsers': parsers, 'metadata_keys_present': md,
        'metadata_note': 'key NAMES only, presence only; BN metadata key names for PDB state are UNVERIFIED',
        'named_ratio': round(ratio, 4) if ratio is not None else None, 'functions_counted': total,
        'verdict': verdict,
        'guid_match': 'UNVERIFIED: no documented API exposes the GUID/age of the PDB that was applied; compare '
                      'codeview.symsrv_key with the PDB you loaded (its symbol-server folder name) before trusting '
                      'symbol-based claims',
    }, truncated=cut)


# ---------------------------------------------------------------------------------------------------------------
# verbs: compute, close, batch
# ---------------------------------------------------------------------------------------------------------------

_COMPUTE_BIN = {
    ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
    ast.BitOr: lambda a, b: a | b, ast.BitXor: lambda a, b: a ^ b, ast.BitAnd: lambda a, b: a & b,
}
_COMPUTE_MAX_BITS = 512


def _cnum(x):
    if abs(x).bit_length() > _COMPUTE_MAX_BITS:
        raise _bad('intermediate value exceeds %d bits' % _COMPUTE_MAX_BITS)
    return x


def _ceval(node, budget):
    budget[0] -= 1
    if budget[0] < 0:
        raise _bad('expression too large (more than 200 nodes)')
    if isinstance(node, ast.Expression):
        return _ceval(node.body, budget)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, int):
            raise _bad('only integer literals are allowed (got %r)' % _clip(node.value, 40))
        return _cnum(node.value)
    if isinstance(node, ast.UnaryOp):
        v = _ceval(node.operand, budget)
        if isinstance(node.op, ast.USub):
            return _cnum(-v)
        if isinstance(node.op, ast.UAdd):
            return v
        if isinstance(node.op, ast.Invert):
            return _cnum(~v)
        raise _bad('unary operator %s is not allowed' % type(node.op).__name__)
    if isinstance(node, ast.BinOp):
        a = _ceval(node.left, budget)
        b = _ceval(node.right, budget)
        op = node.op
        if type(op) in _COMPUTE_BIN:
            return _cnum(_COMPUTE_BIN[type(op)](a, b))
        if isinstance(op, (ast.LShift, ast.RShift)):
            if b < 0 or b > _COMPUTE_MAX_BITS:
                raise _bad('shift count must be 0..%d' % _COMPUTE_MAX_BITS)
            return _cnum(a << b if isinstance(op, ast.LShift) else a >> b)
        if isinstance(op, (ast.FloorDiv, ast.Mod)):
            if b == 0:
                raise _bad('division by zero')
            return _cnum(a // b if isinstance(op, ast.FloorDiv) else a % b)
        if isinstance(op, ast.Pow):
            if b < 0 or b > _COMPUTE_MAX_BITS or (a not in (0, 1, -1) and abs(a).bit_length() * b > _COMPUTE_MAX_BITS + 1):
                raise _bad('power out of range (result must stay within %d bits)' % _COMPUTE_MAX_BITS)
            return _cnum(a ** b)
        if isinstance(op, ast.Div):
            raise _bad('use // (floor division) or % (modulo); true division is not an integer operation')
        raise _bad('binary operator %s is not allowed' % type(op).__name__)
    raise _bad('%s is not allowed in compute (only integer literals, + - * // %% ** << >> & | ^ ~ and parentheses)'
               % type(node).__name__)


def compute(ops, bv, p):
    """Exact integer arithmetic for offsets/sizes (an AST evaluator; never eval; no names, calls or
    attributes). 0x<hex>, 0o, 0b, decimal and 0n<decimal> literals."""
    c = _Ctx(p, 5)
    expr = c.req('expr')
    if len(expr) > 1000:
        raise _bad('expr longer than 1000 characters')
    src = re.sub(r'\b0[nN]([0-9]+)\b', r'\1', expr)
    try:
        tree = ast.parse(src, mode='eval')
    except Exception as e:
        raise _bad('expr does not parse: %s' % _clip(e, 160))
    v = _ceval(tree, [200])
    res = {'expr': expr, 'dec': str(v), 'hex': _hx(v), 'bit_length': abs(v).bit_length(),
           'u32': '0x%08x' % (v & 0xFFFFFFFF), 'u64': '0x%016x' % (v & 0xFFFFFFFFFFFFFFFF)}
    if -(1 << 63) <= v < (1 << 64):
        s64 = v - (1 << 64) if v >= (1 << 63) else v
        res['s64'] = str(s64)
    return c.out(res)


def close_binary(ops, bv, p):
    """Close the scoped view through BinaryOperations.close_owned_view (server-owned views only; POLICY otherwise)."""
    c = _Ctx(p, 30)
    info = _info_for(ops, bv)
    vid = info.get('view_id')
    if not vid:
        raise _api('NOT_FOUND', 'cannot determine the scoped view id', 404)
    f = getattr(ops, 'close_owned_view', None)
    if not callable(f):
        raise _api('UNSUPPORTED_API', 'close_owned_view is not available in this server build', 501)
    r = f(vid)
    return c.out({'closed': str(vid), 'detail': r if isinstance(r, (dict, list, str, int, bool)) or r is None
                  else str(r)})


def load_binary(ops, bv, p):
    """POST /x/loadBinary {filepath, wait:false}: open a binary through the CORE API (bn.load(update_analysis=False),
    then a non-blocking update_analysis; never a UI tab). Idempotent: a server-owned view of the same path whose
    loaded bytes equal the file is returned instead of a second view. Returns at once with {view_id, binary_id,
    analysis_state}; poll analysis_state (bn_binary_info / /status?binary=) until IdleState. wait=true is refused
    (a blocking load would hold the request past the client's tool timeout)."""
    c = _Ctx(p, 30)
    fp = str(p.get('filepath') or p.get('path') or '').strip()
    if not fp:
        raise _bad('filepath is required (an ABSOLUTE path)')
    w = p.get('wait')
    if w not in (None, '', False, 0) and str(w).strip().lower() not in ('0', 'false', 'no', 'off'):
        raise _bad('wait=true is not supported: the load returns at once; poll analysis_state')
    f = getattr(ops, 'load_binary_async', None)
    if not callable(f):
        raise _api('UNSUPPORTED_API', 'load_binary_async is not available in this server build', 501)
    return c.out(f(fp))


_MUTATING_VERBS = {'close_binary', 'load_binary'}


def _verb_name(s):
    t = str(s or '').strip()
    if t.startswith('/x/'):
        t = t[3:]
    elif t.startswith('/'):
        t = t[1:]
    t = re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', t).lower()
    if t.startswith('bn_'):
        t = t[3:]
    return t


def _json_size(obj, lenient=False):
    if lenient:
        s = json.dumps(obj, ensure_ascii=False, separators=(',', ':'), default=str)
    else:
        s = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    return len(s.encode('utf-8'))


def _jsonable(x):
    try:
        return json.loads(json.dumps(x, default=str))
    except Exception:
        return str(x)


def batch(ops, bv, p):
    """Up to 25 read-only items run sequentially in this request's scope; per-item errors and warnings. The batch
    time budget (time_budget_s, default 600 clamped to scan_time_budget_s) bounds every item: an item gets the
    earlier of its own budget and the batch deadline, and an item not started before the deadline answers 'not run'."""
    c = _Ctx(p, 600)
    raw = None
    for k in ('items', 'items_json', 'batch'):
        if p.get(k) is not None:
            raw = p.get(k)
            break
    if raw is None:
        raise _bad('missing items (a JSON list of {"verb": ..., "params": {...}})')
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception as e:
            raise _bad('items is not valid JSON: %s' % _clip(e, 160))
    if not isinstance(raw, list):
        raise _bad('items must be a JSON list')
    if len(raw) > BATCH_MAX_ITEMS:
        raise _bad('at most %d items per batch (got %d)' % (BATCH_MAX_ITEMS, len(raw)))
    results = []
    used = 0
    for idx, it in enumerate(raw):
        try:
            rc.reset_notes()
        except Exception:
            pass
        name = ''
        if c.expired():
            nm = _verb_name(it.get('verb') or it.get('op') or it.get('name')) if isinstance(it, dict) else '?'
            env = {'ok': False, 'verb': nm or '?', 'index': idx, 'error_code': 'BUSY',
                   'error': 'not run: the batch time budget (time_budget_s, at most scan_time_budget_s) is exhausted; '
                            're-send the remaining items'}
            used += _json_size(env, lenient=True)
            results.append(env)
            continue
        try:
            if not isinstance(it, dict):
                raise _bad('item must be an object {"verb": ..., "params": {...}}')
            name = _verb_name(it.get('verb') or it.get('op') or it.get('name'))
            params = it.get('params') if it.get('params') is not None else {}
            if not isinstance(params, dict):
                raise _bad('params must be an object')
            if any(k in params for k in ('binary', 'binary_id')):
                raise _bad('per-item binary is not supported: the batch runs in the scope of its own binary')
            if name == 'batch' or name in _MUTATING_VERBS:
                raise _api('POLICY', 'verb %s is refused inside a batch (only read-only expert verbs)' % name, 403)
            fn = VERB_FUNCS.get(name)
            if fn is None:
                raise _bad('unknown verb %r' % name)
            # the item runs on the earlier of its own budget and the batch deadline (deadline() reads this key)
            params = dict(params)
            params[_ENCLOSING_DEADLINE_KEY] = float(c.dl)
            out = fn(ops, bv, params)
            env = make_envelope(name, out)
            try:
                env['warnings'] = list(env.get('warnings') or []) + [w for w in (rc.warnings() or [])
                                                                    if w not in (env.get('warnings') or [])]
            except Exception:
                pass
        except Exception as e:
            env = error_envelope(name or '?', e)
            try:
                ws = list(rc.warnings() or [])
                if ws:
                    env['warnings'] = ws
            except Exception:
                pass
        env['index'] = idx
        sz = _json_size(env, lenient=True)
        if used + sz > _BATCH_OUTPUT_BUDGET:
            env = {'ok': False, 'verb': name or '?', 'index': idx, 'error_code': 'REFUSED_SIZE',
                   'error': 'batch output budget exhausted (%d bytes); run this item alone' % _BATCH_OUTPUT_BUDGET}
            sz = _json_size(env, lenient=True)
        used += sz
        results.append(env)
    try:
        rc.reset_notes()
    except Exception:
        pass
    not_run = sum(1 for r in results if r.get('error_code') in ('BUSY', 'REFUSED_SIZE') and not r.get('ok'))
    return c.out({'items': results, 'count': len(results), 'ok_count': sum(1 for r in results if r.get('ok')),
                  'not_run_or_refused': not_run}, truncated=not_run > 0)


# ---------------------------------------------------------------------------------------------------------------
# verbs: indirect-dispatch resolution, NDR/MIDL format-string decode, interprocedural slice composition
#
# Three ADDITIVE read-only composition verbs (contract binja-agent-mcp/1, capability expert_v1). They reuse this
# module's existing primitives (the value-set engine via *.get_possible_values, _edges, backward_slice,
# _callers_of, _dominates / _block_of) and never mutate the view. Each is a LEAD, never a verdict.
# ---------------------------------------------------------------------------------------------------------------

def _pvs_target_addrs(pvs_json, cap=256):
    """Concrete target addresses carried by a serialized PossibleValueSet (serialize_pvs output): the single
    'value', the discrete 'values', and lookup-'table' to-values. Ranges are NOT enumerated (they are reported
    verbatim by the caller as value_set). Returns a de-duplicated, order-preserving list of ints, capped."""
    out = []
    seen = set()

    def add(hexval):
        if not isinstance(hexval, str):
            return
        try:
            a = int(hexval, 16)
        except Exception:
            return
        if a in seen:
            return
        seen.add(a)
        out.append(a)

    if isinstance(pvs_json, dict):
        add(pvs_json.get('value'))
        for v in (pvs_json.get('values') or []):
            add(v)
        for e in (pvs_json.get('table') or []):
            if isinstance(e, dict):
                add(e.get('to'))
    return out[:cap]


def resolve_dispatch(ops, bv, p):
    """Resolve the concrete targets of an indirect call / dispatch edge -- the sites _edges (bn_callees) leaves
    'unresolved-indirect' -- by running Binary Ninja value-set analysis on the call destination expression (with
    FromAddressesInLookupTableQueryOption on by default, which is how BN resolves a jump/dispatch table), plus the
    candidate index/opnum operand (the SSA vars the destination reads). With call_site it resolves exactly that
    site (direct or indirect); without, every unresolved-indirect call site in the function. This is the capability
    that lets callgraph / handler_slice / backward_slice stop dead-ending at an unresolved indirect edge. The
    target set is a LEAD, not a proof: an undetermined destination yields no targets."""
    c = _Ctx(p, 30)
    f = resolve_function_strict(bv, c.req('function'))
    max_targets = c.i('max_targets', 64, 1, 4096)
    opt_names, opt_vals = _dfq_options(c)
    opt_vals = list(opt_vals)
    try:
        from binaryninja.enums import DataFlowQueryOption
        lut = getattr(DataFlowQueryOption, 'FromAddressesInLookupTableQueryOption')
        if lut not in opt_vals:
            opt_vals.append(lut)
            if 'FromAddressesInLookupTableQueryOption' not in opt_names:
                opt_names = list(opt_names) + ['FromAddressesInLookupTableQueryOption']
    except Exception:
        pass
    il_of(f, 'mlil', True, True)              # NO_IL (422) with skip status, exactly like the other MLIL verbs
    cache = {}
    site_param = c.s('call_site', '').strip()
    sites = []                                # (va, forced) ; forced = the caller named this exact call_site
    if site_param:
        sites.append((parse_va(bv, site_param), True))
    else:
        for e in _edges(bv, f, cache):
            if e['prov'] == 'unresolved-indirect':
                sites.append((e['site'], False))
    rows = []
    truncated = False
    for (va, forced) in sites:
        if c.expired():
            truncated = True
            c.warn('time-budget: dispatch resolution stopped at %s' % _hx(va))
            break
        try:
            call = _call_at(bv, f, va, True)
        except rc.ApiError:
            if forced:
                raise
            continue                          # an auto indirect site that is a jump, not a call: skip quietly
        dest = getattr(call, 'dest', None)
        const_a = _dest_addr(call)
        method = None
        targets = []
        pvs_json = None
        if const_a is not None:
            method = 'const'
            targets = [const_a]
        elif dest is not None and hasattr(dest, 'get_possible_values'):
            method = 'value-set'
            try:
                pvs_json = serialize_pvs(dest.get_possible_values(opt_vals))
            except Exception as e:
                c.warn('value-set on the dispatch target at %s failed: %s' % (_hx(va), _clip(e, 100)))
                pvs_json = None
            targets = _pvs_target_addrs(pvs_json, max_targets) if pvs_json else []
        index_candidates = []
        if dest is not None:
            for _node, sv in _ssa_reads(dest):
                try:
                    val = serialize_pvs(call.get_ssa_var_possible_values(sv, opt_vals))
                except Exception:
                    val = None
                index_candidates.append({'var': _svname(sv), 'value': val})
                if len(index_candidates) >= 16:
                    break
        tgt_rows = []
        for a in targets[:max_targets]:
            fa = _func_at(bv, a)
            try:
                valid = bool(bv.is_valid_offset(a)) if hasattr(bv, 'is_valid_offset') else None
            except Exception:
                valid = None
            tgt_rows.append({'target_va': _hx(a), 'target_name': _name_at(bv, a) or sym(bv, a),
                             'target_function': _fref(fa) if fa is not None else None, 'valid': valid})
        rows.append({'site': _hx(va), 'sym': sym(bv, va, f),
                     'dest': _text(dest, 160) if dest is not None else None, 'method': method,
                     'resolved_count': len(tgt_rows), 'targets': tgt_rows, 'index_candidates': index_candidates,
                     'value_set': pvs_json})
    return c.out({
        'function': _fref(f), 'options_used': opt_names, 'sites_examined': len(rows), 'resolved': rows,
        'note': 'resolves unresolved-indirect call sites (or the given call_site) to concrete targets by value-set '
                'on the destination expression; feed a target_va back into bn_callees / bn_handler_slice to '
                'continue a dead-ended call graph',
        'caveat': 'a value-set target set is a LEAD, not a proof: an undetermined destination yields no '
                  'targets, and a resolved set reflects only what BN dataflow could bound on the static CFG',
    }, truncated=truncated)


# NDR / MIDL format-character codes and the -Oif PARAM_ATTRIBUTES bit layout. [DOC/RE] verified 2026-10 against
# Microsoft NDR sources: MS Learn "Parameter Descriptors" / "Format Strings" and the Wine / MinGW-w64 ndrtypes.h
# FORMAT_CHARACTER enum + ndr_stubless.h (NDR_PARAM_OIF_BASETYPE / NDR_PARAM_OIF_OTHER). Reconfirm on the target
# build before citing a decode as fact; an unknown code is reported as its raw hex, never guessed.
_NDR_FC = {
    0x01: 'FC_BYTE', 0x02: 'FC_CHAR', 0x03: 'FC_SMALL', 0x04: 'FC_USMALL', 0x05: 'FC_WCHAR', 0x06: 'FC_SHORT',
    0x07: 'FC_USHORT', 0x08: 'FC_LONG', 0x09: 'FC_ULONG', 0x0a: 'FC_FLOAT', 0x0b: 'FC_HYPER', 0x0c: 'FC_DOUBLE',
    0x0d: 'FC_ENUM16', 0x0e: 'FC_ENUM32', 0x0f: 'FC_IGNORE', 0x10: 'FC_ERROR_STATUS_T',
    0x11: 'FC_RP', 0x12: 'FC_UP', 0x13: 'FC_OP', 0x14: 'FC_FP',
    0x15: 'FC_STRUCT', 0x16: 'FC_PSTRUCT', 0x17: 'FC_CSTRUCT', 0x18: 'FC_CPSTRUCT', 0x19: 'FC_CVSTRUCT',
    0x1a: 'FC_BOGUS_STRUCT', 0x1b: 'FC_CARRAY', 0x1c: 'FC_CVARRAY', 0x1d: 'FC_SMFARRAY', 0x1e: 'FC_LGFARRAY',
    0x1f: 'FC_SMVARRAY', 0x20: 'FC_LGVARRAY', 0x21: 'FC_BOGUS_ARRAY',
    0x22: 'FC_C_CSTRING', 0x25: 'FC_C_WSTRING', 0x26: 'FC_CSTRING', 0x29: 'FC_WSTRING',
    0x2a: 'FC_ENCAPSULATED_UNION', 0x2b: 'FC_NON_ENCAPSULATED_UNION',
    0x30: 'FC_BIND_CONTEXT', 0x31: 'FC_BIND_GENERIC', 0x32: 'FC_BIND_PRIMITIVE', 0x33: 'FC_AUTO_HANDLE',
    0x34: 'FC_CALLBACK_HANDLE',
    0x3d: 'FC_STRUCTPAD1', 0x3e: 'FC_STRUCTPAD2', 0x3f: 'FC_STRUCTPAD3', 0x40: 'FC_STRUCTPAD4',
    0x41: 'FC_STRUCTPAD5', 0x42: 'FC_STRUCTPAD6', 0x43: 'FC_STRUCTPAD7',
    0x4d: 'FC_IN_PARAM', 0x50: 'FC_IN_OUT_PARAM', 0x51: 'FC_OUT_PARAM', 0x52: 'FC_RETURN_PARAM',
    0x5b: 'FC_END', 0x5c: 'FC_PAD', 0xb8: 'FC_INT3264', 0xb9: 'FC_UINT3264',
}
# -Oif PARAM_ATTRIBUTES (unsigned short, little-endian) bits; ServerAllocSize is bits 13..15.
_NDR_PARAM_ATTR = (
    (0x0001, 'MustSize'), (0x0002, 'MustFree'), (0x0004, 'IsPipe'), (0x0008, 'IsIn'), (0x0010, 'IsOut'),
    (0x0020, 'IsReturn'), (0x0040, 'IsBasetype'), (0x0080, 'IsByValue'), (0x0100, 'IsSimpleRef'),
    (0x0200, 'IsDontCallFreeInst'), (0x0400, 'SaveForAsyncFinish'),
)
# -Oi direction byte (older interpreter; MS Learn "Parameter Descriptors"). -Oi is 32-bit only.
_NDR_OI_DIR = {0x4d: 'FC_IN_PARAM', 0x50: 'FC_IN_OUT_PARAM', 0x51: 'FC_OUT_PARAM', 0x52: 'FC_RETURN_PARAM'}
_NDR_OI_DIR_FLAGS = {0x4d: ['in'], 0x50: ['in', 'out'], 0x51: ['out'], 0x52: ['return']}


def _fc_name(code):
    return _NDR_FC.get(int(code) & 0xff) or ('FC_0x%02x' % (int(code) & 0xff))


def _ndr_decode_params(data, offset, count, oif=True, cap=1024):
    """Decode `count` NDR/MIDL parameter descriptors at data[offset:]. -Oif records are 6 bytes
    (PARAM_ATTRIBUTES<2> stack_offset<2> {type_format_char<1> unused<1> | type_offset<2>}); -Oi records are 4 bytes
    (direction<1> stack_size<1> type_offset<2>). Pure: no view, no Binary Ninja. Returns (params, consumed,
    truncated) where truncated is True when the data ended before `count` records were read."""
    out = []
    o = int(offset)
    rec = 6 if oif else 4
    truncated = False
    n = min(int(count), cap)
    for i in range(n):
        if o < 0 or o + rec > len(data):
            truncated = True
            break
        if oif:
            attr = _u16(data, o)
            stack_offset = _u16(data, o + 2)
            direction = []
            if attr & 0x0008:
                direction.append('in')
            if attr & 0x0010:
                direction.append('out')
            if attr & 0x0020:
                direction.append('return')
            row = {'index': i, 'param_attributes': '0x%04x' % attr,
                   'attributes': [name for (bit, name) in _NDR_PARAM_ATTR if attr & bit],
                   'direction': direction or ['(none)'], 'stack_offset': '0x%04x' % stack_offset,
                   'server_alloc_size': (attr >> 13) & 0x7, 'is_basetype': bool(attr & 0x0040),
                   'is_simple_ref': bool(attr & 0x0100), 'is_by_value': bool(attr & 0x0080)}
            if attr & 0x0040:
                fc = data[o + 4]
                row['kind'] = 'basetype'
                row['type_format_char'] = '0x%02x' % fc
                row['type'] = _fc_name(fc)
            else:
                row['kind'] = 'complex'
                row['type_offset'] = '0x%04x' % _u16(data, o + 4)
                row['note'] = 'type_offset indexes the type format string (not followed)'
            out.append(row)
        else:
            d = data[o]
            out.append({'index': i, 'kind': 'oi', 'direction_byte': '0x%02x' % d,
                        'direction': list(_NDR_OI_DIR_FLAGS.get(d, [])) or ['(unknown)'],
                        'direction_fc': _NDR_OI_DIR.get(d) or ('FC_0x%02x' % d),
                        'stack_size': '0x%02x' % data[o + 1], 'type_offset': '0x%04x' % _u16(data, o + 2)})
        o += rec
    return out, o - int(offset), truncated


def ndr_decode(ops, bv, p):
    """Decode an NDR/MIDL proc format string's parameter descriptors at va into the per-parameter shape:
    [in]/[out]/[return] direction, base-type FC code or a type_offset into the type format string, and the
    size / simple-ref / by-value attributes (the RE half of reading a MIDL-generated RPC stub). format=oif
    (the 6-byte new interpreter, the default) or oi (the 4-byte old interpreter). Pass count= for an exact
    decode; without it, up to max_params records are read and flagged as not a verified count. With header=1 the
    first bytes are read as a best-effort proc header (handle_type / Oi flags / proc_num / stack_size), which is
    version-dependent and advisory. Read-only; a decode is a LEAD."""
    c = _Ctx(p, 20)
    va = parse_va(bv, c.req('va'))
    fmt = c.s('format', 'oif').strip().lower() or 'oif'
    if fmt not in ('oif', 'oi'):
        raise _bad('format must be oif or oi')
    oif = fmt == 'oif'
    rec = 6 if oif else 4
    count = c.i('count', 0, 0, 1024)
    max_params = c.i('max_params', 32, 1, 1024)
    param_offset = c.i('param_offset', 0, 0, 1000000)
    header = c.b('header', False)
    want = count or max_params
    ln = c.i('length', 0, 0, 8192)
    if ln <= 0:
        ln = min(max(param_offset + want * rec + (8 if header else 0), 64), 8192)
    try:
        data = bytes(bv.read(va, ln) or b'')
    except Exception as e:
        raise rc.NotFoundError('readable bytes at', _hx(va), [_clip(e, 120)])
    if not data:
        raise rc.NotFoundError('readable NDR bytes at', _hx(va), None)
    hdr = None
    if header and len(data) >= 6:
        h0 = data[0]
        hdr = {'handle_type': '0x%02x' % h0, 'handle_fc': (_fc_name(h0) if h0 else 'explicit (0x00)'),
               'oi_flags': '0x%02x' % data[1], 'proc_num': _u16(data, 2), 'stack_size': '0x%04x' % _u16(data, 4),
               'caveat': 'best-effort read of the first bytes; the explicit-handle descriptor and the Oi2 extension '
                         'that carries the parameter count are version-dependent and NOT parsed -- pass count= and '
                         'param_offset= to point at the parameter array exactly'}
    params, consumed, trunc = _ndr_decode_params(data, param_offset, want, oif)
    return c.out({
        'va': _hx(va), 'format': fmt, 'bytes_read': len(data), 'param_offset': param_offset,
        'count_requested': count, 'count_decoded': len(params),
        'count_bounded_by': ('count' if count else
                             'max_params (NOT a verified parameter count; pass count= for an exact decode)'),
        'bytes_consumed': consumed, 'proc_header': hdr, 'params': params,
        'note': 'decodes MIDL/NDR -Oif (6-byte) or -Oi (4-byte) parameter descriptors; FC codes and the '
                'PARAM_ATTRIBUTES bit layout are Microsoft NDR constants (ndrtypes.h / MS Learn), verified 2026-10',
        'caveat': 'a decode is a LEAD: without a verified parameter count the tail may be padding or the '
                  'next proc, and a complex parameter reports only its type_offset into the type format string '
                  '(this verb does not follow it)',
    }, truncated=trunc)


def _frame_gates(bv, fref, onward_site, gates, cache):
    """Gate calls (impersonation / access-decision / identity names in `gates`) in fref's function, each with
    whether it dominates `onward_site` (the call into the deeper frame). Read-only; dominance is intra-procedural
    (same blind spots as undominated_sinks: a multi-path or caller-side gate is invisible, polarity is not read)."""
    rows = []
    if not isinstance(fref, dict):
        return rows
    try:
        f = resolve_function_strict(bv, fref.get('start'))
    except Exception:
        return rows
    sb = _block_of(f, onward_site) if onward_site is not None else None
    for e in _edges(bv, f, cache):
        vs = _name_variants(e['to_name']) if e['to_name'] else set()
        if vs & gates:
            dom = None
            if sb is not None and e['site'] != onward_site:
                dom = _dominates(_block_of(f, e['site']), sb, e['site'], onward_site)
            rows.append({'gate': e['to_name'], 'va': _hx(e['site']), 'sym': sym(bv, e['site'], f),
                         'dominates_call': dom})
    return rows


def interproc_slice(ops, bv, p):
    """Compose backward_slice across param boundaries UP the dispatcher -> handler -> helper call chain: slice the
    seed argument (call_site, arg_index), then for every source of kind 'param' slice the matching argument at each
    caller site, recursively to max_hops, rolling up caller-side gates per frame. A NEW verb -- it CALLS
    backward_slice / _callers_of / the gate detection unchanged and leaves their behaviour byte-for-byte intact.
    Read-only; a LEAD: every caller edge is followed (context-insensitive), so a source may come from a
    path that cannot reach the seed."""
    c = _Ctx(p, 60)
    seed_site = parse_va(bv, c.req('call_site'))
    seed_arg = c.i('arg_index', 0, 0, 1024, strict=True)
    fn_param = c.s('function', '')
    max_hops = c.i('max_hops', 2, 1, 6)
    max_frames = c.i('max_frames', 24, 1, 200)
    gates = set()
    graw = [x.strip() for x in c.s('gate', '').split(',') if x.strip()]
    for g in (graw or list(_DEFAULT_GATES)):
        gates |= _name_variants(g)
    cache = {}
    frames = []
    chain = []
    frontier = []
    truncated = False
    seen = set()
    work = collections.deque()
    work.append((fn_param, seed_site, seed_arg, 0, None))
    while work:
        if len(frames) >= max_frames:
            truncated = True
            c.warn('max_frames=%d reached' % max_frames)
            break
        if c.expired():
            truncated = True
            c.warn('time-budget')
            break
        fspec, site, argi, depth, parent = work.popleft()
        key = (int(site), int(argi))
        if key in seen:
            continue
        seen.add(key)
        fid = len(frames)
        try:
            bs = backward_slice(ops, bv, {'call_site': _hx(site), 'arg_index': argi, 'function': fspec or ''})
            res = bs.get('result') if isinstance(bs, dict) else None
        except rc.ApiError as e:
            frames.append({'id': fid, 'parent': parent, 'depth': depth, 'call_site': _hx(site), 'arg_index': argi,
                           'error': _clip(getattr(e, 'message', str(e)), 200),
                           'error_code': getattr(e, 'code', 'INTERNAL')})
            continue
        if res is None:
            continue
        fref = res.get('function')
        fname = (fref or {}).get('name')
        if fname and fname not in chain:
            chain.append(fname)
        frames.append({'id': fid, 'parent': parent, 'depth': depth, 'function': fref,
                       'call_site': res.get('call_site'), 'arg_index': argi, 'sources': res.get('sources', []),
                       'blind_spots': res.get('blind_spots', []),
                       'gates': _frame_gates(bv, fref, site, gates, cache)})
        if depth + 1 > max_hops:
            continue
        param_sources = [s for s in (res.get('sources') or [])
                         if s.get('kind') == 'param' and isinstance(s.get('index'), int)]
        if not param_sources:
            continue
        func = None
        try:
            if isinstance(fref, dict) and fref.get('start'):
                func = resolve_function_strict(bv, fref['start'])
        except Exception:
            func = None
        callers = _callers_of(bv, func) if func is not None else []
        if not callers:
            for s in param_sources:
                frontier.append({'frame': fid, 'reason': 'param reaches the function boundary with no caller edge',
                                 'param_index': s['index'], 'var': s.get('var')})
            continue
        for s in param_sources:
            for (cf, csite, _prov) in callers:
                work.append(('0x%x' % int(cf.start), csite, s['index'], depth + 1, fid))
    return c.out({
        'seed': {'call_site': _hx(seed_site), 'arg_index': seed_arg}, 'frames': frames, 'chain': chain,
        'frontier': frontier, 'frame_count': len(frames),
        'note': 'each frame is an unchanged backward_slice; param sources are followed UP into every caller (the '
                'dispatcher -> handler -> helper chain, deepest first) with caller-side gates rolled up per frame',
        'caveat': 'interprocedural composition is a LEAD: a slice follows one memory hop only, every '
                  'caller edge is followed (context-insensitive), and gate dominates_call is intra-procedural '
                  'dominance of the onward call site (see undominated_sinks caveats)',
    }, truncated=truncated)


# ---------------------------------------------------------------------------------------------------------------
# envelopes, registry
# ---------------------------------------------------------------------------------------------------------------

def make_envelope(verb, out):
    out = out if isinstance(out, dict) else {}
    return {
        'ok': True,
        'verb': verb,
        'result': out.get('result'),
        'truncated': bool(out.get('truncated', False)),
        'next_offset': out.get('next_offset'),
        'warnings': list(out.get('warnings') or []),
        'limits': dict(out.get('limits') or {}),
    }


def error_envelope(verb, e):
    code = getattr(e, 'code', None)
    if not isinstance(code, str) or not code:
        code = 'INTERNAL'
    msg = getattr(e, 'message', None)
    if not isinstance(msg, str) or not msg:
        msg = str(e) or e.__class__.__name__
    env = {'ok': False, 'verb': verb, 'error': _clip(msg, 2000), 'error_code': code}
    extra = getattr(e, 'extra', None)
    extra = extra if isinstance(extra, dict) else {}
    cands = extra.get('candidates', getattr(e, 'candidates', None))
    if cands:
        try:
            env['candidates'] = _jsonable(list(cands)[:50])
        except Exception:
            pass
    avail = extra.get('available', getattr(e, 'available', None))
    if avail:
        try:
            env['available'] = _jsonable(list(avail)[:50])
        except Exception:
            pass
    for k in ('function_status', 'complexity', 'max_complexity', 'bytes', 'max_bytes'):
        if k in extra:
            env[k] = _jsonable(extra[k])
    return env


def _guard(name, fn, needs_view=True):
    @functools.wraps(fn)
    def wrapped(ops, bv, p):
        if p is None:
            p = {}
        if not isinstance(p, dict):
            raise _bad('parameters must be a mapping')
        if needs_view:
            _require_view(bv)
        out = fn(ops, bv, p)
        try:
            sz = _json_size(out)
        except Exception as e:
            raise _api('INTERNAL', 'result of %s is not JSON-serializable: %s' % (name, _clip(e, 160)), 500)
        if sz > MAX_RESULT_BYTES:
            raise _api('REFUSED_SIZE', 'result of %s is %d bytes, above the %d-byte cap; refine the query (narrow '
                       'the function, lower limit/max_lines/max_chars, or page with offset)'
                       % (name, sz, MAX_RESULT_BYTES), 413, {'bytes': sz, 'max_bytes': MAX_RESULT_BYTES})
        return out
    wrapped.verb_name = name
    return wrapped


VIEWLESS = {'compute', 'server_info', 'load_binary'}

_RAW_VERBS = (
    ('server_info', server_info), ('binary_info', binary_info), ('function_status', function_status),
    ('decompile', decompile), ('il_search', il_search), ('ssa_def', ssa_def), ('ssa_uses', ssa_uses),
    ('backward_slice', backward_slice), ('possible_values', possible_values),
    ('branch_dependence', branch_dependence), ('cfg', cfg), ('dominators', dominators), ('reachable', reachable),
    ('callers', callers), ('callees', callees), ('call_paths', call_paths), ('return_check', return_check),
    ('sinks', sinks), ('undominated_sinks', undominated_sinks), ('stack_frame', stack_frame),
    ('handler_slice', handler_slice), ('resolve_entity', resolve_entity), ('bytes_at', bytes_at),
    ('xrefs', xrefs), ('debug_info_status', debug_info_status), ('uninit_reads', uninit_reads),
    ('resolve_dispatch', resolve_dispatch), ('ndr_decode', ndr_decode), ('interproc_slice', interproc_slice),
    ('compute', compute), ('batch', batch), ('close_binary', close_binary), ('load_binary', load_binary),
)

VERB_FUNCS = {name: _guard(name, fn, name not in VIEWLESS) for (name, fn) in _RAW_VERBS}
