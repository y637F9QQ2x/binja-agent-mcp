# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Offline FAKE of the Binary Ninja object model (tests only; NOT Binary Ninja).

It models ONLY what the binja-agent-mcp plugin touches, so the plugin's
real request/locking/resolution/expert code can run on a host without Binary Ninja:

  FileMetadata (filename, original_filename, modified, close)
  BinaryView   start / end / image_base / functions / symbols / strings / sections / segments / types, read /
               write with a per-byte modification map, get_modification, update_analysis_and_wait,
               analysis_state / analysis_progress, get_code_refs / get_callers / get_callees,
               get_instruction_length / get_disassembly, comments, save (RECORDED, never writes a file)
  Function     a small instruction list with basic blocks (outgoing edges, dominators, post-dominators),
               LLIL / MLIL / MLIL-SSA / HLIL views, an HLIL AST root, parameter / local variables, user variable
               values (set_user_var_value / get_all_user_var_values), analysis_skipped (writes are RECORDED)
  IL           ILNode (operation enum, address, expr_index, instr_index, traverse, possible values,
               branch_dependence, ssa_form / non_ssa_form) and ILFunction (instructions, basic_blocks, ssa_form /
               non_ssa_form, SSA def/use on the SSA form only)
  PossibleValueSet / ValueRange, SSAVariable

MLIL FORMS (as in Binary Ninja, Function.mlil is the NON-SSA form and .ssa_form is a DIFFERENT IL function):
  * A fixture describes MLIL-SSA (the *_SSA operations, MLIL_VAR_PHI, SSAVariable operands). Function.mlil returns
    the non-SSA MLIL DERIVED from it: '_SSA' is dropped from every operation (the ALIASED forms map to SET_VAR /
    VAR), phi statements are dropped, every SSAVariable becomes its Variable, the '#<version>' suffixes are removed
    from the text, and the statements are numbered on their own (instr_index differs from the SSA numbering wherever
    a phi precedes). Instruction indexes carried by a statement ('then N else M' in an IF text, int true / false /
    GOTO dest attributes, branch_dependence keys) are re-keyed into the non-SSA numbering.
  * ILFunction.ssa_form / non_ssa_form link the two functions; ILNode.ssa_form / non_ssa_form link every expression
    to its counterpart. A phi has no non-SSA counterpart: its non_ssa_form raises FakeNoCounterpartError.
  * SSA def/use queries (get_ssa_var_definition, get_ssa_var_uses, get_ssa_memory_definition) refuse the non-SSA
    form (FakeFormError), so a plugin that mixes up the forms fails loudly instead of indexing the wrong function.
    ssa_vars on the non-SSA form returns the SSA form's (the documented Binary Ninja behaviour).
  * The two counterparts SHARE their value-set fixtures and the options_seen probe (dataflow is one analysis seen
    through either form), so a test may inspect either form.
  * LLIL and HLIL have no separate SSA form here (ssa_form / non_ssa_form return the same function).

Rendering is derived from the CURRENT bytes: an instruction whose bytes differ from the file renders as a patched
line in disassembly and HLIL, so a patch_bytes write really changes the decompilation.

ACTIVITY (an overlap detector): Function.hlil enters ACTIVITY for the owning view, sleeps view.delay_s and leaves,
so the HTTP threading tests can prove that two requests did (or did not) run Binary Ninja work at the same time.

standard_program() builds the fixed test program used by every suite; make_standard_file() writes a file whose
bytes identify it, registers the program as the template for that content (by sha256), and open_view() / the
package-level binaryninja.load() turn such a file (or a byte-identical copy) into a fresh BinaryView.
"""

import hashlib
import itertools
import os
import re
import threading
import time

from . import enums as E


# ======================================================================================================== activity

class Activity(object):
    """Counts concurrent fake Binary Ninja work per view and in total (overlap detection for the HTTP tests)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.active = {}
            self.max_same = {}
            self.total = 0
            self.max_total = 0
            self.cross_overlap = set()
            self.entries = 0

    def enter(self, key):
        with self._lock:
            self.entries += 1
            self.active[key] = self.active.get(key, 0) + 1
            self.max_same[key] = max(self.max_same.get(key, 0), self.active[key])
            self.total += 1
            self.max_total = max(self.max_total, self.total)
            others = [k for k, n in self.active.items() if n > 0 and k != key]
            for o in others:
                self.cross_overlap.add(tuple(sorted((str(key), str(o)))))

    def leave(self, key):
        with self._lock:
            self.active[key] = self.active.get(key, 1) - 1
            self.total -= 1

    def snapshot(self):
        with self._lock:
            return {'max_same': dict(self.max_same), 'max_total': self.max_total,
                    'cross_overlap': sorted(self.cross_overlap), 'entries': self.entries}


ACTIVITY = Activity()

_ID_LOCK = threading.Lock()
_EXPR_IDS = itertools.count(1)
TRAVERSE_CALLS = [0]          # how many times ILNode.traverse() was entered (il_search must walk with traverse)
CREATED_VIEWS = []            # every BinaryView built (tests inspect views the plugin loaded and closed)


def _next_expr():
    with _ID_LOCK:
        return next(_EXPR_IDS)


def _hex_or_none(a):
    try:
        return '%#x' % int(a)
    except Exception:
        return str(a)


# ======================================================================================================== small types

class FileMetadata(object):
    def __init__(self, filename=None, original_filename=None):
        self.filename = filename
        self.original_filename = original_filename if original_filename is not None else filename
        self.modified = False
        self.closed = False
        self.close_count = 0

    def close(self):
        self.closed = True
        self.close_count += 1


class Architecture(object):
    def __init__(self, name='x86_64'):
        self.name = name
        self.address_size = 8

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<arch: %s>' % self.name


class Platform(object):
    def __init__(self, arch, name='windows-x86_64'):
        self.arch = arch
        self.name = name

    def __str__(self):
        return self.name


class AddressRange(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end


class Section(object):
    def __init__(self, name, start, end, semantics=E.SectionSemantics.ReadOnlyCodeSectionSemantics):
        self.name = name
        self.start = start
        self.end = end
        self.semantics = semantics
        self.type = 'PE'

    def __len__(self):
        return self.end - self.start


class Segment(object):
    def __init__(self, start, end, data_length=None, flags=0):
        self.start = start
        self.end = end
        self.data_length = (end - start) if data_length is None else data_length
        self.flags = flags
        self.readable = True
        self.writable = False
        self.executable = bool(flags & E.SegmentFlag.SegmentExecutable)


class Symbol(object):
    def __init__(self, sym_type, address, name, raw_name=None, full_name=None):
        self.type = sym_type
        self.address = address
        self.name = name
        self.raw_name = raw_name or name
        self.full_name = full_name or name
        self.short_name = name

    def __repr__(self):
        return '<sym %s %s @ %#x>' % (self.type.name, self.name, self.address)


class StringReference(object):
    def __init__(self, start, value, string_type=E.StringType.AsciiString):
        self.start = start
        self.value = value
        self.length = len(value)
        self.type = string_type

    def __str__(self):
        return self.value


class ReferenceSource(object):
    def __init__(self, function, address):
        self.function = function
        self.address = address
        self.arch = getattr(function, 'arch', None)


class Token(object):
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


class DTLine(object):
    """A DisassemblyTextLine: an address plus text."""

    def __init__(self, address, text):
        self.address = address
        self.text = text

    def __str__(self):
        return self.text


class FakeType(object):
    def __init__(self, text, width=8, members=None, type_class=E.TypeClass.IntegerTypeClass):
        self._text = text
        self.width = width
        self.type_class = type_class
        if members is not None:
            self.members = members

    def __str__(self):
        return self._text

    def __repr__(self):
        return '<type: %s>' % self._text


class StructMember(object):
    def __init__(self, name, type_text, offset):
        self.name = name
        self.type = FakeType(type_text)
        self.offset = offset


class DataVariable(object):
    def __init__(self, address, type_obj):
        self.address = address
        self.type = type_obj


class DebugInfo(object):
    def __init__(self):
        self.parsers = []


class ArchAndAddr(object):
    def __init__(self, arch, addr):
        self.arch = arch
        self.addr = addr

    def __hash__(self):
        return hash(self.addr)

    def __eq__(self, other):
        return isinstance(other, ArchAndAddr) and other.addr == self.addr


class ParsedTypes(object):
    def __init__(self, types):
        self.types = types
        self.variables = {}
        self.functions = {}


# ======================================================================================================== values

class ValueRange(object):
    def __init__(self, start, end, step=1):
        self.start = start
        self.end = end
        self.step = step

    def __repr__(self):
        return '<range: %#x to %#x step %d>' % (self.start, self.end, self.step)


class PossibleValueSet(object):
    """A minimal PossibleValueSet: the attributes exist only when meaningful for the value type."""

    def __init__(self, vtype, **kw):
        self.type = vtype
        for k, v in kw.items():
            setattr(self, k, v)

    def __repr__(self):
        t = self.type.name
        if hasattr(self, 'value'):
            return '<%s %#x>' % (t, self.value)
        if hasattr(self, 'values'):
            return '<%s %s>' % (t, sorted(self.values))
        if hasattr(self, 'ranges'):
            return '<%s %s>' % (t, self.ranges)
        return '<%s>' % t

    def __eq__(self, other):
        return isinstance(other, PossibleValueSet) and repr(self) == repr(other)

    def __hash__(self):
        return hash(repr(self))

    @staticmethod
    def undetermined():
        return PossibleValueSet(E.RegisterValueType.UndeterminedValue)

    @staticmethod
    def constant(v):
        return PossibleValueSet(E.RegisterValueType.ConstantValue, value=int(v))

    @staticmethod
    def constant_ptr(v):
        return PossibleValueSet(E.RegisterValueType.ConstantPointerValue, value=int(v))

    @staticmethod
    def in_set_of_values(values):
        return PossibleValueSet(E.RegisterValueType.InSetOfValues, values=set(int(x) for x in values))

    @staticmethod
    def not_in_set_of_values(values):
        return PossibleValueSet(E.RegisterValueType.NotInSetOfValues, values=set(int(x) for x in values))

    @staticmethod
    def signed_range_value(ranges):
        return PossibleValueSet(E.RegisterValueType.SignedRangeValue, ranges=list(ranges))

    @staticmethod
    def unsigned_range_value(ranges):
        return PossibleValueSet(E.RegisterValueType.UnsignedRangeValue, ranges=list(ranges))


# ======================================================================================================== variables

class Variable(object):
    def __init__(self, name, index, storage=None, source_type=E.VariableSourceType.RegisterVariableSourceType,
                 type_text='int64_t'):
        self.name = name
        self.index = index
        self.storage = index if storage is None else storage
        self.source_type = source_type
        self.type = FakeType(type_text)
        self.identifier = (int(source_type) << 48) | (index << 16) | (self.storage & 0xFFFF)

    def _key(self):
        return (int(self.source_type), self.index, self.storage)

    def __eq__(self, other):
        return isinstance(other, Variable) and other._key() == self._key()

    def __hash__(self):
        return hash(self._key())

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<var %s>' % self.name


class SSAVariable(object):
    def __init__(self, var, version):
        self.var = var
        self.version = int(version)

    def __eq__(self, other):
        return isinstance(other, SSAVariable) and other.var == self.var and other.version == self.version

    def __hash__(self):
        return hash((self.var, self.version))

    def __str__(self):
        return '%s#%d' % (self.var.name, self.version)

    def __repr__(self):
        return '<ssa %s>' % self


# ======================================================================================================== IL

class FakeFormError(ValueError):
    """An SSA-only query on the non-SSA MLIL (the fake refuses it so a form mix-up fails loudly)."""


class FakeNoCounterpartError(ValueError):
    """An SSA expression (a phi) that has no non-SSA counterpart."""


class ILNode(object):
    """One IL expression or statement. Attributes given as keywords become attributes; ILNode values (or lists of
    them) are the children walked by traverse(), in keyword order.

    _form is None (LLIL / HLIL, or a node not built by Function), 'ssa' (MLIL-SSA) or 'non-ssa' (the derived MLIL);
    _peer is the counterpart expression in the other MLIL form (None for a phi)."""

    def __init__(self, op, text='', address=None, expr_index=None, **attrs):
        self.operation = E.il_operation(op)
        self._text = text
        self.address = address
        self.expr_index = _next_expr() if expr_index is None else expr_index
        self.instr_index = None
        self.vars_read = []
        self.vars_written = []
        self.branch_dependence = {}
        self._pvs = None
        self._ssa_pvs = {}
        self._reg_pvs = {}
        self._form = None
        self._peer = None
        self._attr_order = []
        for k, v in attrs.items():
            if k == 'pvs':
                self._pvs = v
                continue
            if k == 'ssa_pvs':
                self._ssa_pvs = dict(v)
                continue
            setattr(self, k, v)
            self._attr_order.append(k)
        self.options_seen = []

    def _children(self):
        out = []
        for k in self._attr_order:
            v = getattr(self, k, None)
            if isinstance(v, ILNode):
                out.append(v)
            elif isinstance(v, (list, tuple)):
                out.extend(x for x in v if isinstance(x, ILNode))
        return out

    def traverse(self, cb, *args, **kwargs):
        """Pre-order walk; yields every non-None cb(node) result (the Binary Ninja 4+ semantics)."""
        TRAVERSE_CALLS[0] += 1
        stack = [self]
        while stack:
            n = stack.pop()
            r = cb(n, *args, **kwargs)
            if r is not None:
                yield r
            stack.extend(reversed(n._children()))

    @property
    def ssa_form(self):
        """The MLIL-SSA counterpart of a non-SSA MLIL expression; any other node is its own SSA form."""
        if self._form == 'non-ssa':
            return self._peer
        return self

    @property
    def non_ssa_form(self):
        """The non-SSA counterpart of an MLIL-SSA expression (a phi has none: FakeNoCounterpartError)."""
        if self._form == 'ssa':
            if self._peer is None:
                raise FakeNoCounterpartError('fake: %s at %s has no non-SSA counterpart (it exists only in MLIL-SSA)'
                                             % (self.operation.name, _hex_or_none(self.address)))
            return self._peer
        return self

    def get_possible_values(self, options=None):
        self.options_seen.append(list(options or []))
        return self._pvs if self._pvs is not None else PossibleValueSet.undetermined()

    def get_ssa_var_possible_values(self, ssa_var, options=None):
        self.options_seen.append(list(options or []))
        return self._ssa_pvs.get(ssa_var, PossibleValueSet.undetermined())

    def get_possible_reg_values(self, reg, options=None):
        return self._reg_pvs.get(reg, PossibleValueSet.undetermined())

    def get_possible_reg_values_after(self, reg, options=None):
        return self._reg_pvs.get(reg, PossibleValueSet.undetermined())

    def _ssa_side(self):
        """The node whose vars_read / vars_written carry SSA versions (the SSA peer of a non-SSA statement)."""
        return self._peer if (self._form == 'non-ssa' and self._peer is not None) else self

    def get_ssa_var_version(self, var):
        for sv in self._ssa_side().vars_read:
            if hasattr(sv, 'version') and getattr(sv, 'var', None) == var:
                return sv.version
        return 0

    def get_ssa_var_version_after(self, var):
        for sv in self._ssa_side().vars_written:
            if hasattr(sv, 'version') and getattr(sv, 'var', None) == var:
                return sv.version
        return self.get_ssa_var_version(var)

    def __str__(self):
        t = self._text
        return t() if callable(t) else str(t)

    def __repr__(self):
        return '<%s: %s>' % (self.operation.name, self)


class ILEdge(object):
    def __init__(self, source, target, etype, back_edge=False):
        self.source = source
        self.target = target
        self.type = etype
        self.back_edge = back_edge


class ILBlock(object):
    def __init__(self, il_function, index, start, end):
        self.il_function = il_function
        self.index = index
        self.start = start
        self.end = end
        self.outgoing_edges = []
        self.incoming_edges = []

    def __len__(self):
        return self.end - self.start

    def __iter__(self):
        return iter(self.il_function.instructions[self.start:self.end])


class HLRoot(object):
    """The HLIL AST root: brace-structured lines (render='ast')."""

    def __init__(self, func, body):
        self._func = func
        self._body = body

    def _lines(self):
        f = self._func
        params = ', '.join('int64_t %s' % v.name for v in f.parameter_vars)
        out = [DTLine(f.start, 'int64_t %s(%s)' % (f.name, params)), DTLine(f.start, '{')]
        for (a, t) in self._body:
            out.append(DTLine(a, '    ' + t))
        out.append(DTLine(f.start, '}'))
        return out

    @property
    def lines(self):
        return self._lines()

    def get_lines(self):
        return self._lines()


class ILFunction(object):
    """One IL function. form is None (LLIL / HLIL: no separate SSA form is modelled), 'ssa' (MLIL-SSA) or 'non-ssa'
    (the MLIL derived from it); _peer is the other MLIL form (linked by _derive_non_ssa_mlil)."""

    def __init__(self, func, level, stmts, blocks=None, root=None, form=None):
        self.source_function = func
        self.level = level
        self.form = form
        self._peer = None
        self._stmts = list(stmts)
        for i, s in enumerate(self._stmts):
            s.instr_index = i
        self._root = root
        self._defs = {}
        self._uses = {}
        ssa_vars = []
        if form != 'non-ssa':
            for s in self._stmts:
                for sv in s.vars_written:
                    self._defs.setdefault(sv, s)
                    if sv not in ssa_vars:
                        ssa_vars.append(sv)
                for sv in s.vars_read:
                    self._uses.setdefault(sv, []).append(s)
                    if sv not in ssa_vars:
                        ssa_vars.append(sv)
        self._ssa_vars = ssa_vars
        self._blocks = []
        spec = blocks if blocks is not None else [(0, len(self._stmts), [])]
        for i, (st, en, _succ) in enumerate(spec):
            self._blocks.append(ILBlock(self, i, st, en))
        for i, (_st, _en, succ) in enumerate(spec):
            for (j, etype) in succ:
                e = ILEdge(self._blocks[i], self._blocks[j], etype, back_edge=j <= i)
                self._blocks[i].outgoing_edges.append(e)
                self._blocks[j].incoming_edges.append(e)

    @property
    def instructions(self):
        return list(self._stmts)

    @property
    def basic_blocks(self):
        return list(self._blocks)

    def __getitem__(self, i):
        return self._stmts[i]

    def __len__(self):
        return len(self._stmts)

    @property
    def ssa_form(self):
        if self.form == 'non-ssa':
            return self._peer
        return self

    @property
    def non_ssa_form(self):
        if self.form == 'ssa':
            return self._peer
        return self

    @property
    def ssa_vars(self):
        if self.form == 'non-ssa':
            return self._peer.ssa_vars
        return list(self._ssa_vars)

    @property
    def root(self):
        return self._root

    def _ssa_only(self, what):
        if self.form == 'non-ssa':
            raise FakeFormError('fake: %s is an MLIL-SSA query and was called on the NON-SSA MLIL of %s (use '
                                '.ssa_form; SSA instruction indexes do not index the non-SSA function)'
                                % (what, getattr(self.source_function, 'name', '?')))

    def get_ssa_var_definition(self, ssa_var):
        self._ssa_only('get_ssa_var_definition')
        return self._defs.get(ssa_var)

    def get_ssa_var_uses(self, ssa_var):
        self._ssa_only('get_ssa_var_uses')
        return list(self._uses.get(ssa_var, []))

    def get_ssa_memory_definition(self, version):
        self._ssa_only('get_ssa_memory_definition')
        return None

    def get_var_definitions(self, var):
        """Statements that write `var` (a Variable). Non-SSA statements write Variables, SSA ones SSAVariables."""
        return [s for s in self._stmts if any(getattr(w, 'var', w) == var for w in s.vars_written)]


class LLILAt(object):
    """What Function.get_llils_at returns: an LLIL statement linked to the NON-SSA MLIL statements at that address
    (as in Binary Ninja, LowLevelILInstruction.mlils / .mlil are non-SSA; .ssa_form reaches MLIL-SSA)."""

    def __init__(self, address, mlils):
        self.address = address
        self.mlils = list(mlils)

    @property
    def mlil(self):
        return self.mlils[0] if self.mlils else None


# ---------------------------------------------------------------------------------------------------- MLIL forms

_PHI_OPS = frozenset({'MLIL_VAR_PHI', 'MLIL_MEM_PHI'})
_ALIASED_TO_NON_SSA = {
    'MLIL_SET_VAR_ALIASED': 'MLIL_SET_VAR', 'MLIL_SET_VAR_ALIASED_FIELD': 'MLIL_SET_VAR_FIELD',
    'MLIL_VAR_ALIASED': 'MLIL_VAR', 'MLIL_VAR_ALIASED_FIELD': 'MLIL_VAR_FIELD',
}
_SSA_VERSION_RE = re.compile(r'(?<=[A-Za-z0-9_])#[0-9]+')
_IF_TARGETS_RE = re.compile(r'\bthen ([0-9]+) else ([0-9]+)\b')
_NODE_INTERNALS = frozenset({
    'operation', '_text', 'address', 'expr_index', 'instr_index', 'vars_read', 'vars_written', 'branch_dependence',
    '_pvs', '_ssa_pvs', '_reg_pvs', '_form', '_peer', '_attr_order', 'options_seen',
})


def _non_ssa_op_name(name):
    """MLIL-SSA operation name -> its non-SSA operation name (an unmodelled result raises KeyError when the node is
    built: a fixture using it fails loudly instead of leaking an SSA operation into the non-SSA form)."""
    if name in _ALIASED_TO_NON_SSA:
        return _ALIASED_TO_NON_SSA[name]
    return name.replace('_SSA', '')


def _derive_non_ssa_mlil(func, ssa_il, ssa_blocks):
    """The non-SSA MLIL of `func`, derived from its MLIL-SSA `ssa_il` (built from block spec `ssa_blocks`) and
    linked to it both ways (functions and every expression). See the module docstring, MLIL FORMS."""
    ssa_stmts = ssa_il.instructions
    fwd = {}                                         # SSA instr_index (non-phi) -> non-SSA instr_index
    for i, s in enumerate(ssa_stmts):
        if s.operation.name not in _PHI_OPS:
            fwd[i] = len(fwd)

    def ns_index(i):
        """Non-SSA index of the statement control reaches at SSA index i (a phi forwards to the next statement of
        its block, where execution actually continues). None if out of range."""
        try:
            j = int(i)
        except Exception:
            return None
        if j < 0:
            return None
        while j < len(ssa_stmts) and j not in fwd:
            j += 1
        return fwd.get(j)

    def ns_text(t, remap_if):
        def conv(s):
            s = _SSA_VERSION_RE.sub('', str(s))
            if remap_if:
                def _r(m):
                    a, b = ns_index(m.group(1)), ns_index(m.group(2))
                    return 'then %s else %s' % (m.group(1) if a is None else a, m.group(2) if b is None else b)
                s = _IF_TARGETS_RE.sub(_r, s)
            return s
        if callable(t):
            return lambda: conv(t())
        return conv(t)

    memo = {}

    def value(v):
        if isinstance(v, ILNode):
            return clone(v)
        if isinstance(v, SSAVariable):
            return v.var
        if isinstance(v, list):
            return [value(x) for x in v]
        if isinstance(v, tuple):
            return tuple(value(x) for x in v)
        return v

    def clone(n, stmt=False):
        k = id(n)
        if k in memo:
            return memo[k]
        if n.operation.name in _PHI_OPS:
            raise ValueError('fake fixture: %s nested inside a statement has no non-SSA form' % n.operation.name)
        is_if = n.operation.name == 'MLIL_IF'
        c = ILNode(_non_ssa_op_name(n.operation.name), ns_text(n._text, is_if), n.address)
        memo[k] = c
        for name, v in list(n.__dict__.items()):
            if name in _NODE_INTERNALS:
                continue
            setattr(c, name, value(v))
        c._attr_order = list(n._attr_order)
        c.vars_read = [value(x) for x in n.vars_read]
        c.vars_written = [value(x) for x in n.vars_written]
        c._pvs = n._pvs                      # shared: one dataflow analysis, seen through either form
        c._ssa_pvs = n._ssa_pvs
        c._reg_pvs = n._reg_pvs
        c.options_seen = n.options_seen
        if stmt:
            bd = {}
            for bi, dep in n.branch_dependence.items():
                if int(bi) not in fwd:
                    raise ValueError('fake fixture: branch_dependence key %r of %s is not a non-phi SSA statement'
                                     % (bi, n))
                bd[fwd[int(bi)]] = dep
            c.branch_dependence = bd
            targets = ('true', 'false') if is_if else (('dest',) if n.operation.name == 'MLIL_GOTO' else ())
            for side in targets:
                v = getattr(n, side, None)
                if isinstance(v, int) and not isinstance(v, bool):
                    m = ns_index(v)
                    setattr(c, side, v if m is None else m)
        c._form, c._peer = 'non-ssa', n
        n._form, n._peer = 'ssa', c
        return c

    ns_stmts = []
    for s in ssa_stmts:
        if s.operation.name in _PHI_OPS:
            s._form, s._peer = 'ssa', None
            continue
        ns_stmts.append(clone(s, stmt=True))
    ns_blocks = None
    if ssa_blocks is not None:
        ns_blocks = []
        for (st, en, succ) in ssa_blocks:
            a = sum(1 for i in fwd if i < st)
            b = a + sum(1 for i in fwd if st <= i < en)
            if b <= a:
                raise ValueError('fake fixture: SSA block [%d, %d) has no non-phi statement' % (st, en))
            ns_blocks.append((a, b, succ))
    ns = ILFunction(func, ssa_il.level, ns_stmts, ns_blocks, form='non-ssa')
    ns._peer, ssa_il._peer = ssa_il, ns
    return ns


# ======================================================================================================== CFG

class Edge(object):
    def __init__(self, source, target, etype, back_edge=False):
        self.source = source
        self.target = target
        self.type = etype
        self.back_edge = back_edge


class BasicBlock(object):
    """A native basic block; iterating it yields ([Token], length) per instruction (current bytes)."""

    def __init__(self, func, index, insns):
        self.function = func
        self.index = index
        self._insns = insns
        self.start = insns[0].addr
        self.end = insns[-1].addr + insns[-1].length
        self.outgoing_edges = []
        self.incoming_edges = []
        self.dominators = []
        self.post_dominators = []
        self.arch = func.arch

    def __iter__(self):
        v = self.function.view
        for ins in self._insns:
            yield ([Token(v._asm_text(ins))], ins.length)

    def __len__(self):
        return len(self._insns)

    @property
    def strict_dominators(self):
        return [b for b in self.dominators if b is not self]

    @property
    def strict_post_dominators(self):
        return [b for b in self.post_dominators if b is not self]

    @property
    def immediate_dominator(self):
        sd = self.strict_dominators
        for b in sd:
            if all((o is b) or (o in b.dominators) for o in sd):
                return b
        return None

    @property
    def immediate_post_dominator(self):
        sd = self.strict_post_dominators
        for b in sd:
            if all((o is b) or (o in b.post_dominators) for o in sd):
                return b
        return None

    @property
    def dominator_tree_children(self):
        return [b for b in self.function.basic_blocks if b.immediate_dominator is self]

    @property
    def post_dominator_tree_children(self):
        return [b for b in self.function.basic_blocks if b.immediate_post_dominator is self]

    @property
    def dominance_frontier(self):
        """DF(X) = {Y : X dominates a predecessor of Y and X does not strictly dominate Y}."""
        out = []
        for b in self.function.basic_blocks:
            if any(self in e.source.dominators for e in b.incoming_edges) and \
                    not (b is not self and self in b.dominators):
                out.append(b)
        return out

    @property
    def post_dominance_frontier(self):
        return []

    def __repr__(self):
        return '<bb #%d %#x-%#x>' % (self.index, self.start, self.end)


def _dominators(blocks, preds_of, roots):
    allb = set(blocks)
    dom = {b: (set([b]) if b in roots else set(allb)) for b in blocks}
    changed = True
    while changed:
        changed = False
        for b in blocks:
            if b in roots:
                continue
            ps = preds_of(b)
            new = set(allb)
            for p in ps:
                new &= dom[p]
            if not ps:
                new = set()
            new |= {b}
            if new != dom[b]:
                dom[b] = new
                changed = True
    return dom


# ======================================================================================================== function

class Insn(object):
    """One fake native instruction."""

    def __init__(self, addr, length, asm, hlil=None, kind='plain', target=None):
        self.addr = addr
        self.length = length
        self.asm = asm
        self.hlil = hlil
        self.kind = kind            # plain | call | cbranch | jump | ret
        self.target = target


class Function(object):
    def __init__(self, view, name, start, insns, blocks=None, params=(), local_vars=(), mlil=None,
                 symbol_type=E.SymbolType.FunctionSymbol):
        self.view = view
        self._name = name
        self.start = start
        self.insns = list(insns)
        self.arch = view.arch
        self.platform = view.platform
        self.symbol = Symbol(symbol_type, start, name)
        self.parameter_vars = list(params)
        self.vars = list(params) + list(local_vars)
        self.stack_layout = []
        self.comment = ''
        self.too_large = False
        self.needs_update = False
        self.has_unresolved_indirect_branches = False
        self.analysis_skip_reason = E.AnalysisSkipReason.NoSkipReason
        self.analysis_skip_override = E.FunctionAnalysisSkipOverride.DefaultFunctionAnalysisSkip
        self._skipped = False
        self.skipped_writes = []
        self.hlil_available = True       # False: hlil / hlil_if_available are None (NO_IL scenarios)
        self.il_generated = True         # False: only the *_if_available forms are None (generate=1 builds it)
        self._user_values = {}
        self._mlil_spec = mlil
        self._mlil = None
        self._blocks = None
        self._block_spec = blocks
        self.reanalyze_calls = 0

    # names ---------------------------------------------------------------------------------------------------
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
        self.symbol = Symbol(self.symbol.type, self.start, value)

    @property
    def raw_name(self):
        return self._name

    @property
    def type(self):
        return FakeType('int64_t %s(%s)' % (self._name, ', '.join('int64_t %s' % v.name for v in self.parameter_vars)))

    # analysis state ------------------------------------------------------------------------------------------
    @property
    def analysis_skipped(self):
        return self._skipped

    @analysis_skipped.setter
    def analysis_skipped(self, value):
        self.skipped_writes.append(bool(value))
        self._skipped = bool(value)

    def reanalyze(self, *a, **k):
        self.reanalyze_calls += 1

    # geometry ------------------------------------------------------------------------------------------------
    @property
    def address_ranges(self):
        return [AddressRange(self.start, self.insns[-1].addr + self.insns[-1].length)]

    @property
    def total_bytes(self):
        return sum(i.length for i in self.insns)

    @property
    def highest_address(self):
        return self.insns[-1].addr

    @property
    def lowest_address(self):
        return self.start

    def _insn_at(self, a):
        for i in self.insns:
            if i.addr == a:
                return i
        return None

    @property
    def basic_blocks(self):
        if self._blocks is None:
            self._build_blocks()
        return list(self._blocks)

    def _build_blocks(self):
        spec = self._block_spec
        if spec is None:
            spec = [([i.addr for i in self.insns], [])]
        by_addr = {i.addr: i for i in self.insns}
        blocks = []
        for idx, (addrs, _succ) in enumerate(spec):
            blocks.append(BasicBlock(self, idx, [by_addr[a] for a in addrs]))
        for idx, (_addrs, succ) in enumerate(spec):
            for (j, etype) in succ:
                e = Edge(blocks[idx], blocks[j], etype, back_edge=j <= idx)
                blocks[idx].outgoing_edges.append(e)
                blocks[j].incoming_edges.append(e)
        dom = _dominators(blocks, lambda b: [e.source for e in b.incoming_edges], {blocks[0]})
        exits = {b for b in blocks if not b.outgoing_edges}
        pdom = _dominators(blocks, lambda b: [e.target for e in b.outgoing_edges], exits)
        for b in blocks:
            b.dominators = sorted(dom[b], key=lambda x: x.index)
            b.post_dominators = sorted(pdom[b], key=lambda x: x.index)
        self._blocks = blocks

    def get_basic_block_at(self, a, arch=None):
        for b in self.basic_blocks:
            if b.start <= a < b.end:
                return b
        return None

    @property
    def call_sites(self):
        return [ReferenceSource(self, i.addr) for i in self.insns if i.kind == 'call']

    def is_call_instruction(self, a, arch=None):
        i = self._insn_at(a)
        return bool(i is not None and i.kind == 'call')

    # IL --------------------------------------------------------------------------------------------------------
    def _mlil_il(self):
        """The NON-SSA MLIL (what Function.mlil is in Binary Ninja). The fixture spec describes MLIL-SSA, which is
        built first and reached through .ssa_form; the non-SSA form is derived from it (module docstring)."""
        if self._mlil is None:
            spec = self._mlil_spec(self) if callable(self._mlil_spec) else None
            if spec is None:
                stmts, blocks = self._default_mlil()
            else:
                stmts, blocks = spec
            ssa = ILFunction(self, 'mlil', stmts, blocks, form='ssa')
            self._mlil = _derive_non_ssa_mlil(self, ssa, blocks)
        return self._mlil

    def _default_mlil(self):
        """MLIL-SSA statements for a function without an explicit spec (one per instruction)."""
        stmts = []
        for n, i in enumerate(self.insns):
            if i.kind == 'call':
                tgt = ILNode('MLIL_CONST_PTR', '%#x' % i.target, i.addr, constant=i.target)
                stmts.append(ILNode('MLIL_CALL_SSA', '%s()' % self.view._name_of(i.target), i.addr,
                                    dest=tgt, params=[], output=[]))
            elif i.kind == 'ret':
                stmts.append(ILNode('MLIL_RET', 'return', i.addr, src=[]))
            elif i.kind == 'strref':
                c = ILNode('MLIL_CONST_PTR', '%#x' % i.target, i.addr, constant=i.target)
                v = SSAVariable(Variable('rcx_%d' % n, 100 + n), 1)
                s = ILNode('MLIL_SET_VAR_SSA', '%s = %#x' % (v, i.target), i.addr, dest=v, src=c)
                s.vars_written = [v]
                stmts.append(s)
            else:
                v = SSAVariable(Variable('var_%d' % n, 200 + n), 1)
                c = ILNode('MLIL_CONST', str(n), i.addr, constant=n)
                s = ILNode('MLIL_SET_VAR_SSA', '%s = %d' % (v, n), i.addr, dest=v, src=c)
                s.vars_written = [v]
                stmts.append(s)
        return stmts, None

    def _hlil_il(self):
        self.view._tick()
        if not self.hlil_available:
            return None
        v = self.view
        body = []
        stmts = []
        for i in self.insns:
            if i.hlil is None:
                continue
            txt = v._hlil_text(i)
            body.append((i.addr, txt))
            stmts.append(ILNode('HLIL_NOP', txt, i.addr, expr_index=len(stmts) + 1))
        return ILFunction(self, 'hlil', stmts, None, root=HLRoot(self, body))

    def _llil_il(self):
        stmts = [ILNode('LLIL_NOP', self.view._asm_text(i), i.addr, expr_index=n + 1) for n, i in enumerate(self.insns)]
        return ILFunction(self, 'llil', stmts)

    @property
    def hlil(self):
        return self._hlil_il()

    @property
    def hlil_if_available(self):
        return self._hlil_il() if self.il_generated else None

    @property
    def mlil(self):
        return self._mlil_il() if self.hlil_available else None

    @property
    def mlil_if_available(self):
        return self._mlil_il() if (self.hlil_available and self.il_generated) else None

    @property
    def llil(self):
        return self._llil_il()

    @property
    def llil_if_available(self):
        return self._llil_il() if self.il_generated else None

    @property
    def high_level_il(self):
        return self.hlil

    @property
    def medium_level_il(self):
        return self.mlil

    @property
    def low_level_il(self):
        return self.llil

    def get_llils_at(self, addr, arch=None):
        il = self.mlil
        if il is None:
            return []
        ms = [s for s in il.instructions if s.address == addr]
        return [LLILAt(addr, ms)] if ms else []

    def get_llil_at(self, addr, arch=None):
        r = self.get_llils_at(addr)
        return r[0] if r else None

    # user variable values (UIDF pins) ------------------------------------------------------------------------
    def set_user_var_value(self, var, def_addr, value, after=True):
        self._user_values.setdefault(var, {})[ArchAndAddr(self.arch, int(def_addr))] = value

    def get_all_user_var_values(self):
        return {k: dict(v) for k, v in self._user_values.items() if v}

    def clear_user_var_value(self, var, def_addr):
        self._user_values.get(var, {}).pop(ArchAndAddr(self.arch, int(def_addr)), None)

    def __repr__(self):
        return '<func: %s@%#x>' % (self._name, self.start)


# ======================================================================================================== view

class BinaryView(object):
    def __init__(self, path, data, image_base, tag='', delay_s=0.0, original_filename=None):
        self.file = FileMetadata(path, original_filename if original_filename is not None else path)
        self._orig = bytes(data)
        self._mem = bytearray(data)
        self._mod = bytearray(len(data))
        self.image_base = image_base
        self.start = image_base
        self.end = image_base + len(data)
        self.entry_point = image_base
        self.tag = tag
        self.delay_s = float(delay_s)
        self.gate = None                 # threading.Event: Function.hlil blocks until it is set (lock-order tests)
        self.gate_timeout_s = 30.0
        self.key =os.path.normcase(os.path.abspath(path)) + '#' + str(id(self))
        self.arch = Architecture('x86_64')
        self.platform = Platform(self.arch)
        self.view_type = 'PE'
        self.parent_view = None
        self.analysis_state = E.AnalysisState.IdleState
        self.analysis_progress = 'Idle'
        self.debug_info = DebugInfo()
        self._funcs = {}
        self._symbols = []
        self._strings = []
        self._comments = {}
        self.sections = {}
        self.segments = []
        self.types = {}
        self.data_vars = {}
        self.save_calls = []
        self.update_calls = 0
        self.write_calls = []
        self.lock = threading.Lock()
        CREATED_VIEWS.append(self)

    # activity ------------------------------------------------------------------------------------------------
    def _tick(self):
        """Simulated Binary Ninja work: sleep delay_s, or block while `gate` (a threading.Event) is not set."""
        gate = self.gate
        if self.delay_s > 0 or gate is not None:
            ACTIVITY.enter(self.key)
            try:
                if gate is not None:
                    gate.wait(self.gate_timeout_s)
                if self.delay_s > 0:
                    time.sleep(self.delay_s)
            finally:
                ACTIVITY.leave(self.key)

    # bytes ---------------------------------------------------------------------------------------------------
    def _off(self, a):
        return a - self.start

    def read(self, addr, length):
        o = self._off(addr)
        if length <= 0 or o < 0 or o >= len(self._mem):
            return b''
        return bytes(self._mem[o:o + length])

    def read_int(self, addr, size, sign=True, endian=None):
        b = self.read(addr, size)
        if len(b) != size:
            raise ValueError('read past the end')
        return int.from_bytes(b, 'little', signed=sign)

    def write(self, addr, data, except_on_relocation=True):
        data = bytes(data)
        o = self._off(addr)
        if o < 0 or o >= len(self._mem):
            return 0
        n = min(len(data), len(self._mem) - o)
        for k in range(n):
            self._mem[o + k] = data[k]
            self._mod[o + k] = int(E.ModificationStatus.Changed) if data[k] != self._orig[o + k] else 0
        self.write_calls.append((addr, data[:n]))
        self.file.modified = True
        return n

    def get_modification(self, addr, length=None):
        if length is None:
            o = self._off(addr)
            return E.ModificationStatus(self._mod[o]) if 0 <= o < len(self._mod) else E.ModificationStatus.Original
        out = []
        for a in range(addr, addr + length):
            o = self._off(a)
            out.append(E.ModificationStatus(self._mod[o]) if 0 <= o < len(self._mod) else E.ModificationStatus.Original)
        return out

    def modified_count(self):
        return sum(1 for b in self._mod if b)

    def is_valid_offset(self, addr):
        return self.start <= addr < self.end

    def is_offset_readable(self, addr):
        return self.is_valid_offset(addr)

    def __len__(self):
        return self.end - self.start

    # rendering -----------------------------------------------------------------------------------------------
    def _patched(self, ins):
        o = self._off(ins.addr)
        return any(self._mod[o:o + ins.length])

    def _asm_text(self, ins):
        if self._patched(ins):
            return 'db ' + ' '.join('%02x' % b for b in self.read(ins.addr, ins.length)) + '  ; patched'
        return ins.asm

    def _hlil_text(self, ins):
        if self._patched(ins):
            return '/* patched: %s */ nop' % self.read(ins.addr, ins.length).hex()
        return ins.hlil

    def _name_of(self, a):
        f = self._funcs.get(a)
        if f is not None:
            return f.name
        s = self.get_symbol_at(a)
        return s.name if s is not None else ('sub_%x' % a)

    # functions -----------------------------------------------------------------------------------------------
    def add_fake_function(self, func):
        self._funcs[func.start] = func
        if self.get_symbol_at(func.start) is None:
            self._symbols.append(func.symbol)
        return func

    @property
    def functions(self):
        return [self._funcs[a] for a in sorted(self._funcs)]

    def get_function_at(self, addr, plat=None):
        return self._funcs.get(addr)

    def get_functions_at(self, addr):
        f = self._funcs.get(addr)
        return [f] if f else []

    def get_functions_by_name(self, name, plat=None, ordered_filter=None):
        return [f for f in self.functions if f.name == name]

    def get_functions_containing(self, addr, plat=None):
        out = []
        for f in self.functions:
            for r in f.address_ranges:
                if r.start <= addr < r.end:
                    out.append(f)
                    break
        return out

    def get_recent_function_at(self, addr):
        return self._funcs.get(addr)

    def add_function(self, addr, plat=None, auto_discovered=False, func_type=None):
        return None

    def create_user_function(self, addr, plat=None):
        return None

    def update_function(self, *a, **k):
        return None

    # analysis --------------------------------------------------------------------------------------------------
    def update_analysis_and_wait(self):
        self.update_calls += 1

    def update_analysis(self):
        self.update_calls += 1

    # symbols ---------------------------------------------------------------------------------------------------
    def add_symbol(self, sym):
        self._symbols.append(sym)
        return sym

    def get_symbol_at(self, addr, namespace=None):
        for s in self._symbols:
            if s.address == addr:
                return s
        return None

    def get_symbols(self, start=None, length=None, namespace=None):
        if start is None:
            return list(self._symbols)
        return [s for s in self._symbols if start <= s.address < start + (length or 1)]

    def get_symbols_by_name(self, name, namespace=None, ordered_filter=None):
        return [s for s in self._symbols if s.name == name or s.raw_name == name]

    def get_symbol_by_raw_name(self, name, namespace=None):
        for s in self._symbols:
            if s.raw_name == name:
                return s
        return None

    def get_symbol_by_name(self, name, namespace=None):
        for s in self._symbols:
            if s.name == name:
                return s
        return None

    def get_symbols_of_type(self, sym_type, start=None, length=None, namespace=None):
        return [s for s in self._symbols if s.type == sym_type]

    @property
    def symbols(self):
        out = {}
        for s in self._symbols:
            out.setdefault(s.name, []).append(s)
        return out

    def define_user_symbol(self, sym):
        self._symbols = [s for s in self._symbols if s.address != sym.address]
        self._symbols.append(sym)

    def define_auto_symbol(self, sym):
        self.define_user_symbol(sym)

    # refs --------------------------------------------------------------------------------------------------------
    def _call_refs(self, addr):
        out = []
        for f in self.functions:
            for i in f.insns:
                if i.kind == 'call' and i.target == addr:
                    out.append(ReferenceSource(f, i.addr))
        out.sort(key=lambda r: r.address)
        return out

    def get_code_refs(self, addr, length=None, max_items=None):
        out = self._call_refs(addr)
        return out[:max_items] if max_items is not None else out

    def get_callers(self, addr):
        return self._call_refs(addr)

    def get_callees(self, addr, func=None, arch=None):
        for f in ([func] if func is not None else self.functions):
            i = f._insn_at(addr) if f is not None else None
            if i is not None and i.kind == 'call' and i.target is not None:
                return [i.target]
        return []

    def get_data_refs(self, addr, length=None, max_items=None):
        out = []
        for f in self.functions:
            for i in f.insns:
                if i.kind == 'strref' and i.target == addr:
                    out.append(i.addr)
        return out[:max_items] if max_items is not None else out

    def get_code_refs_for_type(self, name, max_items=None):
        return []

    def get_code_refs_for_type_field(self, name, offset, max_items=None):
        return []

    def get_data_refs_for_type(self, name, max_items=None):
        return []

    # instructions -------------------------------------------------------------------------------------------------
    def _insn(self, addr):
        for f in self.functions:
            i = f._insn_at(addr)
            if i is not None:
                return i
        return None

    def get_instruction_length(self, addr, arch=None):
        i = self._insn(addr)
        return i.length if i is not None else 0

    def get_disassembly(self, addr, arch=None):
        i = self._insn(addr)
        return self._asm_text(i) if i is not None else None

    # data, strings, types ------------------------------------------------------------------------------------------
    def get_sections_at(self, addr):
        return [s for s in self.sections.values() if s.start <= addr < s.end]

    def get_segment_at(self, addr):
        for s in self.segments:
            if s.start <= addr < s.end:
                return s
        return None

    def get_string_at(self, addr, partial=False):
        for s in self._strings:
            if s.start == addr:
                return s
        return None

    @property
    def strings(self):
        return list(self._strings)

    def get_strings(self, start=None, length=None):
        if start is None:
            return list(self._strings)
        return [s for s in self._strings if start <= s.start < start + (length or 0)]

    def get_type_by_name(self, name):
        return self.types.get(str(name))

    def get_type_at(self, addr):
        dv = self.data_vars.get(addr)
        return dv.type if dv is not None else None

    def get_data_var_at(self, addr):
        return self.data_vars.get(addr)

    def parse_types_from_string(self, text, options=None, include_dirs=None):
        import re
        types = {}
        for m in re.finditer(r'\b(struct|union|enum)\s+([A-Za-z_]\w*)', str(text)):
            types[m.group(2)] = FakeType('%s %s' % (m.group(1), m.group(2)), 4, [], E.TypeClass.StructureTypeClass)
        if not types:
            raise SyntaxError('fake parser: no struct/union/enum definition found')
        return ParsedTypes(types)

    def define_user_type(self, name, type_obj):
        self.types[str(name)] = type_obj

    # comments ----------------------------------------------------------------------------------------------------
    def set_comment_at(self, addr, text):
        if text is None or text == '':
            self._comments.pop(addr, None)
        else:
            self._comments[addr] = text

    def get_comment_at(self, addr):
        return self._comments.get(addr, '')

    # persistence ---------------------------------------------------------------------------------------------------
    def save(self, dest, *a, **k):
        """RECORDED ONLY: the fake never writes a file (tests assert that the plugin never calls it)."""
        self.save_calls.append(str(dest))
        return True

    def create_database(self, *a, **k):
        self.save_calls.append('create_database')
        return True

    def __repr__(self):
        return '<FakeBinaryView %s tag=%s>' % (self.file.filename, self.tag)


# ======================================================================================================== program

IMAGE_BASE = 0x140000000
IMAGE_SIZE = 0x4000

A_MAIN = IMAGE_BASE + 0x1000
A_HELPER = IMAGE_BASE + 0x1100
A_LEAF = IMAGE_BASE + 0x1180
A_DISPATCH = IMAGE_BASE + 0x1200
A_SLICE = IMAGE_BASE + 0x1300
A_GETSIZE = IMAGE_BASE + 0x1380
A_DUP1 = IMAGE_BASE + 0x1400
A_DUP2 = IMAGE_BASE + 0x1480
A_VALUES = IMAGE_BASE + 0x1500
A_GETINPUT = IMAGE_BASE + 0x1580
A_STR_CONFIG = IMAGE_BASE + 0x2000
A_COUNTER = IMAGE_BASE + 0x2010
A_STR_PREFIX = IMAGE_BASE + 0x2020
A_IMP_CREATEFILE = IMAGE_BASE + 0x3000
A_IMP_MEMCPY = IMAGE_BASE + 0x3008

# addresses the tests use
SLICE_CALL = A_SLICE + 0x1b          # call memcpy(dst, src, i#2)
DISPATCH_JNE = A_DISPATCH + 0x4      # conditional branch
VALUES_DEF = A_VALUES                # counter#1 = 5 (a definition site of counter)
VALUES_CALL = A_VALUES + 0x4         # n#1 = getinput()


def _insn_bytes(ins, seed):
    """Deterministic, never-all-0x90 bytes for one instruction."""
    out = bytearray()
    for k in range(ins.length):
        out.append((0x48 + 7 * k + seed + (ins.addr & 0xff)) & 0xff)
    if all(b == 0x90 for b in out):
        out[0] = 0x48
    return bytes(out)


def _program_insns(tag):
    t = tag or '-'
    P = {}
    P['main'] = (A_MAIN, [
        Insn(A_MAIN + 0x0, 4, 'push rbp', 'int64_t rax = tagcheck("%s")' % t),
        Insn(A_MAIN + 0x4, 5, 'call %#x' % A_HELPER, 'helper(0x10)', 'call', A_HELPER),
        Insn(A_MAIN + 0x9, 5, 'call %#x' % A_DISPATCH, 'dispatch(rax)', 'call', A_DISPATCH),
        Insn(A_MAIN + 0xe, 6, 'call qword [rel %#x]' % A_IMP_CREATEFILE, 'CreateFileW("config.ini")', 'call',
             A_IMP_CREATEFILE),
        Insn(A_MAIN + 0x14, 7, 'lea rcx, [rel %#x]' % A_STR_CONFIG, 'g_counter = 1', 'strref', A_STR_CONFIG),
        Insn(A_MAIN + 0x1b, 1, 'retn', 'return rax', 'ret'),
    ], None)
    P['helper'] = (A_HELPER, [
        Insn(A_HELPER + 0x0, 4, 'mov eax, ecx', 'int32_t x = arg1'),
        Insn(A_HELPER + 0x4, 5, 'call %#x' % A_LEAF, 'leaf()', 'call', A_LEAF),
        Insn(A_HELPER + 0x9, 1, 'retn', 'return x', 'ret'),
    ], None)
    P['leaf'] = (A_LEAF, [
        Insn(A_LEAF + 0x0, 4, 'xor eax, eax', 'return 0'),
        Insn(A_LEAF + 0x4, 1, 'retn', None, 'ret'),
    ], None)
    P['dispatch'] = (A_DISPATCH, [
        Insn(A_DISPATCH + 0x0, 4, 'cmp ecx, 0x1', None),
        Insn(A_DISPATCH + 0x4, 2, 'jne %#x' % (A_DISPATCH + 0x10), 'if (arg1 == 1)', 'cbranch', A_DISPATCH + 0x10),
        Insn(A_DISPATCH + 0x6, 5, 'call %#x' % A_LEAF, 'leaf()', 'call', A_LEAF),
        Insn(A_DISPATCH + 0xb, 5, 'jmp %#x' % (A_DISPATCH + 0x15), None, 'jump', A_DISPATCH + 0x15),
        Insn(A_DISPATCH + 0x10, 5, 'call %#x' % A_HELPER, 'helper(arg1)', 'call', A_HELPER),
        Insn(A_DISPATCH + 0x15, 1, 'retn', 'return 0', 'ret'),
    ], [
        ([A_DISPATCH + 0x0, A_DISPATCH + 0x4], [(1, E.BranchType.FalseBranch), (2, E.BranchType.TrueBranch)]),
        ([A_DISPATCH + 0x6, A_DISPATCH + 0xb], [(3, E.BranchType.UnconditionalBranch)]),
        ([A_DISPATCH + 0x10], [(3, E.BranchType.UnconditionalBranch)]),
        ([A_DISPATCH + 0x15], []),
    ])
    P['slice_target'] = (A_SLICE, [
        Insn(A_SLICE + 0x0, 4, 'mov rbx, rcx', 'int64_t x = arg1'),
        Insn(A_SLICE + 0x4, 4, 'mov edx, 0x10', 'int64_t y = 0x10'),
        Insn(A_SLICE + 0x8, 5, 'call %#x' % A_GETSIZE, 'int64_t z = getsize()', 'call', A_GETSIZE),
        Insn(A_SLICE + 0xd, 4, 'lea rax, [rbx+rdx]', 'int64_t i = x + y'),
        Insn(A_SLICE + 0x11, 4, 'add rax, rdi', 'do { i = i + z'),
        Insn(A_SLICE + 0x15, 4, 'cmp rax, 0x100', None),
        Insn(A_SLICE + 0x19, 2, 'jb %#x' % (A_SLICE + 0x11), '} while (i u< 0x100)', 'cbranch', A_SLICE + 0x11),
        Insn(A_SLICE + 0x1b, 5, 'call qword [rel %#x]' % A_IMP_MEMCPY, 'memcpy(dst, src, i)', 'call', A_IMP_MEMCPY),
        Insn(A_SLICE + 0x20, 1, 'retn', 'return', 'ret'),
    ], [
        ([A_SLICE + 0x0, A_SLICE + 0x4, A_SLICE + 0x8, A_SLICE + 0xd], [(1, E.BranchType.UnconditionalBranch)]),
        ([A_SLICE + 0x11, A_SLICE + 0x15, A_SLICE + 0x19], [(1, E.BranchType.TrueBranch), (2, E.BranchType.FalseBranch)]),
        ([A_SLICE + 0x1b, A_SLICE + 0x20], []),
    ])
    P['getsize'] = (A_GETSIZE, [
        Insn(A_GETSIZE + 0x0, 5, 'mov eax, 0x20', 'return 0x20'),
        Insn(A_GETSIZE + 0x5, 1, 'retn', None, 'ret'),
    ], None)
    P['dup#1'] = (A_DUP1, [Insn(A_DUP1, 4, 'mov eax, 1', 'return 1'), Insn(A_DUP1 + 4, 1, 'retn', None, 'ret')], None)
    P['dup#2'] = (A_DUP2, [Insn(A_DUP2, 4, 'mov eax, 2', 'return 2'), Insn(A_DUP2 + 4, 1, 'retn', None, 'ret')], None)
    P['values_fn'] = (A_VALUES, [
        Insn(A_VALUES + 0x0, 4, 'mov ecx, 0x5', 'int32_t counter = 5'),
        Insn(A_VALUES + 0x4, 5, 'call %#x' % A_GETINPUT, 'int32_t n = getinput()', 'call', A_GETINPUT),
        Insn(A_VALUES + 0x9, 4, 'cmp eax, 0x10', None),
        Insn(A_VALUES + 0xd, 2, 'ja %#x' % (A_VALUES + 0x20), 'if (n u<= 0x10)', 'cbranch', A_VALUES + 0x20),
        Insn(A_VALUES + 0xf, 4, 'mov ecx, eax', 'counter = n'),
        Insn(A_VALUES + 0x13, 5, 'call qword [rel %#x]' % A_IMP_MEMCPY, 'memcpy(buf, src, counter)', 'call',
             A_IMP_MEMCPY),
        Insn(A_VALUES + 0x20, 1, 'retn', 'return', 'ret'),
    ], [
        ([A_VALUES + 0x0, A_VALUES + 0x4, A_VALUES + 0x9, A_VALUES + 0xd],
         [(1, E.BranchType.FalseBranch), (2, E.BranchType.TrueBranch)]),
        ([A_VALUES + 0xf, A_VALUES + 0x13], [(2, E.BranchType.UnconditionalBranch)]),
        ([A_VALUES + 0x20], []),
    ])
    P['getinput'] = (A_GETINPUT, [
        Insn(A_GETINPUT + 0x0, 5, 'mov eax, 0x40', 'return 0x40'),
        Insn(A_GETINPUT + 0x5, 1, 'retn', None, 'ret'),
    ], None)
    return P


def _slice_mlil(func):
    """MLIL-SSA of slice_target with a phi cycle: i#2 = phi(i#1, i#3); i#3 = i#2 + z#1.

    Instruction indexes here (the IF text, branch_dependence keys) are SSA numbering: the phi is index 4, the IF 6.
    The derived non-SSA MLIL has no phi, so there the IF is index 5 and memcpy's branch_dependence is {5: ...}."""
    arg1, dst, src = func.parameter_vars[0], func.parameter_vars[1], func.parameter_vars[2]
    x, y, z, i = [v for v in func.vars if v.name in ('x', 'y', 'z', 'i')]
    s = SSAVariable
    a = A_SLICE

    def var(sv, addr):
        n = ILNode('MLIL_VAR_SSA', str(sv), addr, src=None)
        n.src = sv           # an SSAVariable, not a child node
        return n

    st = []
    n0 = ILNode('MLIL_SET_VAR_SSA', 'x#1 = arg1#0', a + 0x0, dest=s(x, 1), src=var(s(arg1, 0), a))
    n0.vars_written, n0.vars_read = [s(x, 1)], [s(arg1, 0)]
    st.append(n0)
    n1 = ILNode('MLIL_SET_VAR_SSA', 'y#1 = 0x10', a + 0x4, dest=s(y, 1),
                src=ILNode('MLIL_CONST', '0x10', a + 0x4, constant=0x10), pvs=PossibleValueSet.constant(0x10))
    n1.vars_written = [s(y, 1)]
    st.append(n1)
    n2 = ILNode('MLIL_CALL_SSA', 'z#1 = getsize()', a + 0x8, output=[s(z, 1)],
                dest=ILNode('MLIL_CONST_PTR', '%#x' % A_GETSIZE, a + 0x8, constant=A_GETSIZE), params=[])
    n2.vars_written = [s(z, 1)]
    st.append(n2)
    n3 = ILNode('MLIL_SET_VAR_SSA', 'i#1 = x#1 + y#1', a + 0xd, dest=s(i, 1),
                src=ILNode('MLIL_ADD', 'x#1 + y#1', a + 0xd, left=var(s(x, 1), a + 0xd), right=var(s(y, 1), a + 0xd)))
    n3.vars_written, n3.vars_read = [s(i, 1)], [s(x, 1), s(y, 1)]
    st.append(n3)
    n4 = ILNode('MLIL_VAR_PHI', 'i#2 = phi(i#1, i#3)', a + 0x11, dest=s(i, 2))
    n4.src = [s(i, 1), s(i, 3)]
    n4.vars_written, n4.vars_read = [s(i, 2)], [s(i, 1), s(i, 3)]
    st.append(n4)
    n5 = ILNode('MLIL_SET_VAR_SSA', 'i#3 = i#2 + z#1', a + 0x11, dest=s(i, 3),
                src=ILNode('MLIL_ADD', 'i#2 + z#1', a + 0x11, left=var(s(i, 2), a + 0x11), right=var(s(z, 1), a + 0x11)))
    n5.vars_written, n5.vars_read = [s(i, 3)], [s(i, 2), s(z, 1)]
    st.append(n5)
    n6 = ILNode('MLIL_IF', 'if (i#3 u< 0x100) then 4 else 7', a + 0x19,
                condition=ILNode('MLIL_CMP_ULT', 'i#3 u< 0x100', a + 0x19, left=var(s(i, 3), a + 0x19),
                                 right=ILNode('MLIL_CONST', '0x100', a + 0x19, constant=0x100)))
    n6.vars_read = [s(i, 3)]
    st.append(n6)
    n7 = ILNode('MLIL_CALL_SSA', 'memcpy(dst#0, src#0, i#2)', a + 0x1b, output=[],
                dest=ILNode('MLIL_CONST_PTR', '%#x' % A_IMP_MEMCPY, a + 0x1b, constant=A_IMP_MEMCPY),
                params=[var(s(dst, 0), a + 0x1b), var(s(src, 0), a + 0x1b), var(s(i, 2), a + 0x1b)])
    n7.vars_read = [s(dst, 0), s(src, 0), s(i, 2)]
    st.append(n7)
    st.append(ILNode('MLIL_RET', 'return', a + 0x20, src=[]))
    st[6].branch_dependence = {}
    st[7].branch_dependence = {6: E.ILBranchDependence.FalseBranchDependent}
    blocks = [(0, 4, [(1, E.BranchType.UnconditionalBranch)]),
              (4, 7, [(1, E.BranchType.TrueBranch), (2, E.BranchType.FalseBranch)]),
              (7, 9, [])]
    return st, blocks


def _values_mlil(func):
    """MLIL-SSA of values_fn: counter#1 = 5 (constant), n#1 = getinput() (undetermined), 3 CFG edges."""
    counter, n = [v for v in func.vars if v.name in ('counter', 'n')]
    s = SSAVariable
    a = A_VALUES

    def var(sv, addr):
        node = ILNode('MLIL_VAR_SSA', str(sv), addr)
        node.src = sv
        return node

    st = []
    n0 = ILNode('MLIL_SET_VAR_SSA', 'counter#1 = 5', a + 0x0, dest=s(counter, 1),
                src=ILNode('MLIL_CONST', '5', a, constant=5), pvs=PossibleValueSet.constant(5),
                ssa_pvs={s(counter, 1): PossibleValueSet.constant(5)})
    n0.vars_written = [s(counter, 1)]
    st.append(n0)
    n1 = ILNode('MLIL_CALL_SSA', 'n#1 = getinput()', a + 0x4, output=[s(n, 1)],
                dest=ILNode('MLIL_CONST_PTR', '%#x' % A_GETINPUT, a + 0x4, constant=A_GETINPUT), params=[],
                pvs=PossibleValueSet.undetermined())
    n1.vars_written = [s(n, 1)]
    st.append(n1)
    n2 = ILNode('MLIL_IF', 'if (n#1 u> 0x10) then 5 else 3', a + 0xd,
                condition=ILNode('MLIL_CMP_UGT', 'n#1 u> 0x10', a + 0xd, left=var(s(n, 1), a + 0xd),
                                 right=ILNode('MLIL_CONST', '0x10', a + 0xd, constant=0x10)))
    n2.vars_read = [s(n, 1)]
    st.append(n2)
    n3 = ILNode('MLIL_SET_VAR_SSA', 'counter#2 = n#1', a + 0xf, dest=s(counter, 2), src=var(s(n, 1), a + 0xf),
                pvs=PossibleValueSet.unsigned_range_value([ValueRange(0, 0x10, 1)]))
    n3.vars_written, n3.vars_read = [s(counter, 2)], [s(n, 1)]
    st.append(n3)
    p0 = var(s(counter, 2), a + 0x13)
    p0._pvs = PossibleValueSet.in_set_of_values([1, 2, 0x10])
    n4 = ILNode('MLIL_CALL_SSA', 'memcpy(buf, src, counter#2)', a + 0x13, output=[],
                dest=ILNode('MLIL_CONST_PTR', '%#x' % A_IMP_MEMCPY, a + 0x13, constant=A_IMP_MEMCPY), params=[p0])
    n4.vars_read = [s(counter, 2)]
    st.append(n4)
    st.append(ILNode('MLIL_RET', 'return', a + 0x20, src=[]))
    blocks = [(0, 3, [(1, E.BranchType.FalseBranch), (2, E.BranchType.TrueBranch)]),
              (3, 5, [(2, E.BranchType.UnconditionalBranch)]),
              (5, 6, [])]
    return st, blocks


def _main_mlil(func):
    stmts, _b = func._default_mlil()
    return stmts, None


def program_bytes(tag):
    """The file image of the standard program for `tag` (instruction bytes + strings + tag-dependent filler)."""
    seed = int(hashlib.sha256(('fake-bn:' + str(tag)).encode('utf-8')).hexdigest()[:2], 16)
    data = bytearray(((i * 31 + seed) & 0xff) for i in range(IMAGE_SIZE))
    data[0:2] = b'MZ'
    marker = ('FAKEBN-TAG:%s' % tag).encode('utf-8')[:200]
    data[0x40:0x40 + len(marker)] = marker
    for _name, (_start, insns, _blocks) in _program_insns(tag).items():
        for ins in insns:
            o = ins.addr - IMAGE_BASE
            data[o:o + ins.length] = _insn_bytes(ins, seed)
    for a, s in ((A_STR_CONFIG, b'config.ini\x00'), (A_STR_PREFIX, b'MyLogPrefix\x00')):
        o = a - IMAGE_BASE
        data[o:o + len(s)] = s
    o = A_COUNTER - IMAGE_BASE
    data[o:o + 4] = (7).to_bytes(4, 'little')
    return bytes(data)


def build_standard_view(path, image_base=IMAGE_BASE, tag='', delay_s=0.0, data=None, extra=None):
    """A BinaryView of the standard program at image_base (functions are always laid out for IMAGE_BASE; a different
    image_base shifts start/end only)."""
    if data is None:
        with open(path, 'rb') as f:
            data = f.read()
    v = BinaryView(path, data, image_base, tag=tag, delay_s=delay_s)
    shift = image_base - IMAGE_BASE
    v.entry_point = A_MAIN + shift
    v.sections = {
        '.text': Section('.text', IMAGE_BASE + 0x1000 + shift, IMAGE_BASE + 0x1800 + shift),
        '.rdata': Section('.rdata', IMAGE_BASE + 0x2000 + shift, IMAGE_BASE + 0x2800 + shift,
                          E.SectionSemantics.ReadOnlyDataSectionSemantics),
        '.idata': Section('.idata', IMAGE_BASE + 0x3000 + shift, IMAGE_BASE + 0x3100 + shift,
                          E.SectionSemantics.ReadOnlyDataSectionSemantics),
    }
    v.segments = [Segment(IMAGE_BASE + shift, IMAGE_BASE + IMAGE_SIZE + shift, IMAGE_SIZE,
                          int(E.SegmentFlag.SegmentReadable | E.SegmentFlag.SegmentExecutable))]
    if shift:
        return v          # a rebased load: no functions at the expected addresses (the start check fails first)
    progs = _program_insns(tag)
    pv = {}
    for name, (start, insns, blocks) in progs.items():
        fname = name.split('#')[0]
        params, local_vars, mlil = (), (), None
        if fname == 'slice_target':
            params = (Variable('arg1', 1), Variable('dst', 2), Variable('src', 3))
            local_vars = (Variable('x', 10), Variable('y', 11), Variable('z', 12), Variable('i', 13))
            mlil = _slice_mlil
        elif fname == 'values_fn':
            local_vars = (Variable('counter', 20), Variable('n', 21))
            mlil = _values_mlil
        elif fname in ('helper', 'dispatch'):
            params = (Variable('arg1', 1),)
        f = Function(v, fname, start, insns, blocks, params, local_vars, mlil)
        v.add_fake_function(f)
        pv[fname] = f
    v.add_symbol(Symbol(E.SymbolType.ImportedFunctionSymbol, A_IMP_CREATEFILE, 'CreateFileW', '__imp_CreateFileW'))
    v.add_symbol(Symbol(E.SymbolType.ImportedFunctionSymbol, A_IMP_MEMCPY, 'memcpy', '__imp_memcpy'))
    v.add_symbol(Symbol(E.SymbolType.DataSymbol, A_COUNTER, 'g_counter', 'g_counter'))
    v._strings = [StringReference(A_STR_CONFIG, 'config.ini'), StringReference(A_STR_PREFIX, 'MyLogPrefix')]
    v.data_vars = {A_COUNTER: DataVariable(A_COUNTER, FakeType('int32_t', 4))}
    v.types = {
        'MyStruct': FakeType('struct MyStruct', 0x10, [StructMember('a', 'int32_t', 0), StructMember('b', 'char*', 8)],
                             E.TypeClass.StructureTypeClass),
    }
    if extra is not None:
        extra(v)
    return v


def add_big_function(view, name='bigfn', start=None, count=6000, width=400):
    """Add a function whose MLIL has `count` statements of `width`-character text (for the 2 MiB result cap)."""
    start = IMAGE_BASE + 0x1700 if start is None else start
    insns = [Insn(start + k, 1, 'nop', None) for k in range(min(count, 0x100))]

    def mlil(func):
        st = []
        filler = 'X' * max(1, width - 40)
        for k in range(count):
            st.append(ILNode('MLIL_NOP', 'big_%05d %s' % (k, filler), start + (k % len(insns))))
        return st, None

    f = Function(view, name, start, insns, None, (), (), mlil)
    view.add_fake_function(f)
    return f


# ======================================================================================================== templates

_TEMPLATES = {}
_TEMPLATES_LOCK = threading.Lock()


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def register_template(sha, builder):
    """builder(path, image_base) -> BinaryView, used by open_view() / binaryninja.load() for files with this sha256."""
    with _TEMPLATES_LOCK:
        _TEMPLATES[sha] = builder


def make_standard_file(directory, basename, tag, delay_s=0.0, extra=None):
    """Write the standard program for `tag` to <directory>/<basename> and register it as a load template."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, basename)
    data = program_bytes(tag)
    with open(path, 'wb') as f:
        f.write(data)
    sha = hashlib.sha256(data).hexdigest()

    def builder(p, base, _tag=tag, _delay=delay_s, _extra=extra):
        return build_standard_view(p, base, _tag, _delay, extra=_extra)

    register_template(sha, builder)
    return path


def open_view(path, options=None):
    """The fake loader: a fresh BinaryView for `path` (template by content sha256; else an empty raw view)."""
    base = IMAGE_BASE
    if isinstance(options, dict) and options.get('loader.imageBase') is not None:
        base = int(options['loader.imageBase'])
    if not os.path.isfile(path):
        raise IOError('fake loader: no such file: %s' % path)
    sha = sha256_of(path)
    with _TEMPLATES_LOCK:
        b = _TEMPLATES.get(sha)
    if b is not None:
        return b(path, base)
    with open(path, 'rb') as f:
        data = f.read()
    return BinaryView(path, data, base, tag='raw')
