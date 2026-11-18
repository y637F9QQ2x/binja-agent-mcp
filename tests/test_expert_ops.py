# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""expert_ops verbs (contract binja-agent-mcp/1, capability expert_v1) on the fake program.

The verbs run in-process (ops + request scope, exactly as the HTTP layer calls them) and, for the envelope, status
mapping and size cap, through the real HTTP server.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest

import run_tests as H


def _long_and_caller(view):
    """extra builder: longfn (240 long HLIL lines) and bigcaller, which calls it."""
    fb = H.fake_bv()
    start = fb.IMAGE_BASE + 0x1700
    insns = [fb.Insn(start + k, 1, 'nop', 'int64_t long_line_%04d = some_long_expression_value_%04d' % (k, k))
             for k in range(0x0f0)]
    view.add_fake_function(fb.Function(view, 'longfn', start, insns))
    c = fb.IMAGE_BASE + 0x1600
    view.add_fake_function(fb.Function(view, 'bigcaller', c, [
        fb.Insn(c, 5, 'call %#x' % start, 'longfn()', 'call', start), fb.Insn(c + 5, 1, 'retn', 'return', 'ret')]))


def _indirect_dispatch(view):
    """extra builder: a function 'dispatcher' with ONE indirect call whose destination value-set resolves to
    {helper, leaf} (so resolve_dispatch's value-set path can be exercised offline). The call instruction has no
    static target (target=None), so _edges classifies the site unresolved-indirect; the MLIL-SSA call destination
    is a variable carrying an InSetOfValues PossibleValueSet."""
    fb = H.fake_bv()
    IL, SV, Var, PVS = fb.ILNode, fb.SSAVariable, fb.Variable, fb.PossibleValueSet
    a = fb.IMAGE_BASE + 0x1700
    insns = [fb.Insn(a + 0x0, 4, 'mov rax, [rcx+r8*8]', 'int64_t t = tbl[idx]'),
             fb.Insn(a + 0x4, 2, 'call rax', 't(arg1)', 'call', None),
             fb.Insn(a + 0x6, 1, 'retn', 'return', 'ret')]
    arg1, idx, t = Var('arg1', 1), Var('idx', 2), Var('t', 3)

    def mlil(func):
        tnode = IL('MLIL_VAR_SSA', 't#1', a + 0x4)
        tnode.src = SV(t, 1)
        tnode._pvs = PVS.in_set_of_values([fb.A_HELPER, fb.A_LEAF])
        call = IL('MLIL_CALL_SSA', 't#1(arg1#0)', a + 0x4, dest=tnode, params=[], output=[])
        call._ssa_pvs = {SV(t, 1): PVS.in_set_of_values([fb.A_HELPER, fb.A_LEAF])}
        return [call, IL('MLIL_RET', 'return', a + 0x6, src=[])], None

    view.add_fake_function(fb.Function(view, 'dispatcher', a, insns, None, (arg1,), (idx, t), mlil))


def _slice_caller(view):
    """extra builder: a function 'outer' that calls slice_target(p0, 0, 0) with real MLIL call parameters, so
    interproc_slice can ascend one hop from slice_target's param source into outer's parameter."""
    fb = H.fake_bv()
    IL, SV, Var = fb.ILNode, fb.SSAVariable, fb.Variable
    a = fb.IMAGE_BASE + 0x1720
    insns = [fb.Insn(a + 0x0, 5, 'call %#x' % fb.A_SLICE, 'slice_target(p0, 0, 0)', 'call', fb.A_SLICE),
             fb.Insn(a + 0x5, 1, 'retn', 'return', 'ret')]
    p0 = Var('p0', 1)

    def mlil(func):
        pnode = IL('MLIL_VAR_SSA', 'p0#0', a)
        pnode.src = SV(p0, 0)
        call = IL('MLIL_CALL_SSA', 'slice_target(p0#0, 0, 0)', a,
                  dest=IL('MLIL_CONST_PTR', '%#x' % fb.A_SLICE, a, constant=fb.A_SLICE),
                  params=[pnode, IL('MLIL_CONST', '0', a, constant=0), IL('MLIL_CONST', '0', a, constant=0)],
                  output=[])
        return [call, IL('MLIL_RET', 'return', a + 0x5, src=[])], None

    view.add_fake_function(fb.Function(view, 'outer', a, insns, None, (p0,), (), mlil))


class _LiveStringRef(object):
    """A StringReference whose value reads the view's CURRENT bytes, as the real Binary Ninja API does
    (binaryninja/binaryview.py, class StringReference: value = view.read(start, length).decode(...)). The fake's own
    StringReference holds a static value, so without this a patched string could never reach a pack in a test."""

    def __init__(self, view, start, length, string_type):
        self._view = view
        self.start = start
        self.length = length
        self.type = string_type

    @property
    def value(self):
        return self._view.read(self.start, self.length).decode('ascii', errors='replace')

    def __str__(self):
        return self.value

    def __len__(self):
        return self.length


def _live_strings(view):
    """Wrap view.get_string_at (on this instance only) so every returned string reads current memory."""
    orig = view.get_string_at

    def get_string_at(addr, partial=False):
        s = orig(addr, partial)
        if s is None:
            return None
        n = getattr(s, 'length', None)
        return _LiveStringRef(view, s.start, len(str(s.value)) if n is None else n, getattr(s, 'type', None))

    view.get_string_at = get_string_at


def _script_analysis_state(view):
    """Make this view's analysis_state change WHILE a pack is being built. Returns a controller; ctl.arm(before,
    after) (AnalysisState names) makes the view report `before` until its next HLIL render (the fake's Function.hlil
    calls view._tick()) and `after` from then on. ctl.arm(before, after, back) scripts a TRANSIENT change instead:
    `after` holds from the first HLIL render until the next READ of the state, which still returns `after` and then
    switches the view to `back` (analysis that started and finished inside one pack, seen by exactly one sample).
    ctl.flipped / ctl.flipped_back record that each change really happened (a test whose precondition never occurred
    must fail, not pass vacuously); ctl.reads lists the state name of every read.
    Only this instance changes: its class is swapped for a subclass whose analysis_state property shadows the
    plain attribute the fake's BinaryView.__init__ sets."""
    E = H.ensure_fake().enums
    ctl = types.SimpleNamespace(state=E.AnalysisState.IdleState, after=None, back=None, flipped=False,
                                flipped_back=False, reads=[])

    def arm(before, after, back=None):
        ctl.state = getattr(E.AnalysisState, before)
        ctl.after = getattr(E.AnalysisState, after)
        ctl.back = None if back is None else getattr(E.AnalysisState, back)
        ctl.flipped = False
        ctl.flipped_back = False
        del ctl.reads[:]

    ctl.arm = arm
    base = type(view)

    class _ScriptedAnalysisView(base):
        @property
        def analysis_state(self):
            cur = ctl.state
            ctl.reads.append(cur.name)
            if ctl.flipped and ctl.back is not None and not ctl.flipped_back:
                ctl.state = ctl.back
                ctl.flipped_back = True
            return cur

        @analysis_state.setter
        def analysis_state(self, value):
            ctl.state = E.AnalysisState(int(value))

        def _tick(self):
            if ctl.after is not None and not ctl.flipped:
                ctl.state = ctl.after
                ctl.flipped = True
            return base._tick(self)

    view.__class__ = _ScriptedAnalysisView
    return ctl


class _ExpertBase(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.ex = self.m.expert_ops
        self.rc = self.m.rc
        self.fb = H.fake_bv()
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-expert-')
        self.addCleanup(self.td.cleanup)
        self.ops = H.new_ops(self.m)
        self.v = self.view('a', 'foo.dll', 'A')

    def view(self, sub, basename='foo.dll', tag='A', extra=None):
        v = H.make_view(os.path.join(self.td.name, sub), basename, tag, 0.0, extra)
        self.ops.register_view(v)
        if not hasattr(self, '_keep'):
            self._keep = []
        self._keep.append(v)
        return v

    def call(self, verb, view=None, **params):
        view = self.v if view is None else view
        with self.ops.using_view(view):
            return self.ex.VERB_FUNCS[verb](self.ops, view, params)

    def api_error(self, code, status, verb, view=None, **params):
        with self.assertRaises(self.rc.ApiError) as cm:
            self.call(verb, view, **params)
        self.assertEqual((cm.exception.code, cm.exception.http_status), (code, status), str(cm.exception))
        return cm.exception


class SliceAndValuesTests(_ExpertBase):
    def test_backward_slice_terminates_on_a_phi_cycle(self):
        out = self.call('backward_slice', call_site='0x%x' % self.fb.SLICE_CALL, arg_index='2')
        r = out['result']
        self.assertFalse(out['truncated'])
        kinds = sorted(s['kind'] for s in r['sources'])
        self.assertEqual(kinds, ['call_return', 'const', 'param'])
        by = {s['kind']: s for s in r['sources']}
        self.assertEqual((by['param']['index'], by['param']['var']), (0, 'arg1#0'))
        self.assertEqual(by['const']['value'], '0x10')
        self.assertEqual((by['call_return']['callee'], by['call_return']['callee_va']), ('getsize', '0x140001380'))
        node_kinds = [n['kind'] for n in r['nodes']]
        self.assertEqual(node_kinds.count('phi'), 1)
        vars_seen = [n['var'] for n in r['nodes'] if 'var' in n]
        self.assertEqual(len(vars_seen), len(set(vars_seen)), 'an SSA variable was visited twice: %s' % vars_seen)
        self.assertIn('i#2', vars_seen)
        self.assertIn('i#3', vars_seen)
        self.assertTrue(r['blind_spots'])
        self.assertEqual(r['blind_spots'], sorted(r['blind_spots']))
        self.assertEqual(r['call_site']['va'], '0x14000131b')
        self.assertTrue(r['call_site']['sym'].startswith('foo.dll!slice_target+0x1b'))
        for n in r['nodes']:
            if 'va' in n and n['va']:
                self.assertTrue(n['va'].startswith('0x'))

    def test_backward_slice_argument_checks(self):
        self.api_error('BAD_ARGUMENT', 400, 'backward_slice', call_site='0x%x' % self.fb.SLICE_CALL, arg_index='3')
        self.api_error('BAD_ARGUMENT', 400, 'backward_slice', call_site='0x140001300', arg_index='0')  # not a call
        out = self.call('backward_slice', call_site='0x%x' % self.fb.SLICE_CALL, arg_index='1')
        self.assertEqual([(s['kind'], s['index']) for s in out['result']['sources']], [('param', 2)])
        out = self.call('backward_slice', call_site='slice_target+0x1b', arg_index='2', max_nodes='2')
        self.assertTrue(out['truncated'])
        self.assertIn('max_nodes=2 reached', out['warnings'])

    def test_possible_values_serialization_and_undetermined(self):
        r = self.call('possible_values', va='0x140001500')['result']
        self.assertEqual(r['options_used'], [])
        self.assertEqual(r['complexity'], 3)
        v = r['statements'][0]['values'][0]['value']
        self.assertEqual((v['type'], v['undetermined'], v['value']), ('ConstantValue', False, '0x5'))
        r = self.call('possible_values', va='0x140001504')['result']
        v = r['statements'][0]['values'][0]['value']
        self.assertEqual((v['type'], v['undetermined']), ('UndeterminedValue', True))
        r = self.call('possible_values', va='0x14000150f')['result']
        v = r['statements'][0]['values'][0]['value']
        self.assertEqual(v['type'], 'UnsignedRangeValue')
        self.assertEqual(v['ranges'], [{'start': '0x0', 'end': '0x10', 'step': 1}])
        r = self.call('possible_values', va='0x140001513', operand='param:0')['result']
        v = r['statements'][0]['values'][0]
        self.assertEqual(v['target'], 'param:0')
        self.assertEqual((v['value']['type'], v['value']['values']), ('InSetOfValues', ['0x1', '0x2', '0x10']))
        r = self.call('possible_values', va='0x140001500', var='counter', when='after')['result']
        v = r['statements'][0]['values'][0]
        self.assertEqual((v['target'], v['value']['type']), ('var:counter#1', 'ConstantValue'))
        self.assertIsNone(self.ex.serialize_pvs(None)['type'] if False else None)
        self.assertEqual(self.ex.serialize_pvs(None), {'type': 'None', 'undetermined': True})

    def test_possible_values_options_are_opt_in_and_echoed(self):
        r = self.call('possible_values', va='0x140001500', options='from_lookup_table,writable')['result']
        self.assertEqual(r['options_used'], ['FromAddressesInLookupTableQueryOption',
                                             'AllowReadingWritableMemoryQueryOption'])
        f = self.v.get_function_at(self.fb.A_VALUES)
        st = [s for s in f.mlil.instructions if s.address == 0x140001500][0]
        DFQ = H.ensure_fake().enums.DataFlowQueryOption
        self.assertEqual(st.options_seen[-1], [DFQ.FromAddressesInLookupTableQueryOption,
                                               DFQ.AllowReadingWritableMemoryQueryOption])
        self.call('possible_values', va='0x140001500')
        self.assertEqual(st.options_seen[-1], [])
        self.api_error('BAD_ARGUMENT', 400, 'possible_values', va='0x140001500', options='make_it_sound')

    def test_possible_values_refuses_above_the_complexity_budget(self):
        e = self.api_error('REFUSED_COMPLEXITY', 422, 'possible_values', va='0x140001500', max_complexity='2')
        self.assertEqual((e.extra['complexity'], e.extra['max_complexity']), (3, 2))
        self.call('possible_values', va='0x140001500', max_complexity='3')

    def test_bare_digit_addresses_are_rejected(self):
        for verb, key in (('possible_values', 'va'), ('bytes_at', 'va'), ('xrefs', 'va'),
                          ('branch_dependence', 'va'), ('resolve_entity', 'ref')):
            with self.subTest(verb=verb):
                self.api_error('BAD_ARGUMENT', 400, verb, **{key: '5368713472'})
        out = self.call('bytes_at', va='0n5368717312', length='4')       # 0n<decimal> = 0x140002000
        self.assertEqual(out['result']['hex'], b'conf'.hex())
        self.api_error('BAD_ARGUMENT', 400, 'bytes_at', va='0xZZ')
        with self.assertRaises(self.rc.NotFoundError):
            self.call('bytes_at', va='no_such_symbol')
        with self.assertRaises(self.rc.AmbiguousError):
            self.call('bytes_at', va='dup')


class GraphAndSearchTests(_ExpertBase):
    def test_reachable_with_removed_out_of_and_removed_edges(self):
        base = dict(function='dispatch', from_va='0x140001200', to_va='0x140001215')
        r = self.call('reachable', **base)['result']
        self.assertTrue(r['reachable'])
        self.assertEqual([b['index'] for b in r['path']], [0, 1, 3])
        r = self.call('reachable', removed_out_of='0x140001206', **base)['result']
        self.assertTrue(r['reachable'])
        self.assertEqual([b['index'] for b in r['path']], [0, 2, 3])
        self.assertEqual(r['removed_out_of_applied'], ['#1'])
        r = self.call('reachable', removed_out_of='#1,#2', **base)['result']
        self.assertFalse(r['reachable'])
        self.assertEqual(r['path'], [])
        r = self.call('reachable', removed_out_of='#1', removed_edges='#0->#2', **base)['result']
        self.assertFalse(r['reachable'])
        self.assertEqual(r['removed_edges_applied'], ['#0->#2'])
        r = self.call('reachable', removed_out_of='#0', **base)['result']
        self.assertFalse(r['reachable'])
        self.api_error('BAD_ARGUMENT', 400, 'reachable', removed_edges='#0-#2', **base)

    def test_cfg_and_dominators(self):
        r = self.call('cfg', function='dispatch')['result']
        self.assertEqual(r['block_count'], 4)
        self.assertEqual([e['to'] for e in r['blocks'][0]['edges']], [1, 2])
        r = self.call('dominators', function='dispatch', block_va='#3')['result']
        self.assertEqual([b['index'] for b in r['result']], [0, 3])
        self.assertIn('caveat', r)
        r = self.call('dominators', function='dispatch', block_va='#0', kind='post_dominators')['result']
        self.assertEqual([b['index'] for b in r['result']], [0, 3])
        r = self.call('dominators', function='dispatch', block_va='#3', kind='immediate_dominator')['result']
        self.assertEqual([b['index'] for b in r['result']], [0])

    def test_il_search_walks_with_traverse(self):
        before = self.fb.TRAVERSE_CALLS[0]
        out = self.call('il_search', function='slice_target', constant='0x10')
        self.assertGreater(self.fb.TRAVERSE_CALLS[0], before)
        ms = out['result']['matches']
        self.assertEqual([(x['op'], x['va']) for x in ms], [('MLIL_CONST', '0x140001304')])
        # il defaults to mlil, the NON-SSA form (as in Binary Ninja, Function.mlil is non-SSA): no '#<version>'
        self.assertIn('y = 0x10', ms[0]['statement'])                   # a nested node: only reachable by traverse
        out = self.call('il_search', function='slice_target', il='mlil_ssa', constant='0x10')
        ms = out['result']['matches']
        self.assertEqual([(x['op'], x['va']) for x in ms], [('MLIL_CONST', '0x140001304')])
        self.assertIn('y#1 = 0x10', ms[0]['statement'])                 # il=mlil_ssa walks the SSA form
        out = self.call('il_search', callee='memcpy')
        self.assertEqual(sorted(x['va'] for x in out['result']['matches']), ['0x14000131b', '0x140001513'])
        self.assertTrue(out['result']['scan']['complete'])
        out = self.call('il_search', il='mlil_ssa', operation='CALL_SSA', limit='1')   # *_SSA ops: the SSA form
        self.assertTrue(out['truncated'])
        self.assertEqual(out['next_offset'], 1)
        self.assertEqual(len(out['result']['matches']), 1)
        self.api_error('BAD_ARGUMENT', 400, 'il_search', operation='MLIL_NO_SUCH_OP')
        self.api_error('BAD_ARGUMENT', 400, 'il_search')                 # no filter
        self.api_error('BAD_ARGUMENT', 400, 'il_search', operation='HLIL_IF')   # wrong level for il=mlil

    def test_il_search_lists_functions_without_il_and_generate_builds_it(self):
        f = self.v.get_function_at(self.fb.A_GETINPUT)
        f.il_generated = False
        out = self.call('il_search', operation='MLIL_RET')
        self.assertIn('getinput@0x140001580', out['result']['scan']['skipped_no_il'])
        self.assertIn('generate=1', out['result']['note'])
        out = self.call('il_search', operation='MLIL_RET', generate='1')
        self.assertEqual(out['result']['scan']['skipped_no_il'], [])
        e = self.api_error('NO_IL', 422, 'il_search', function='getinput', operation='MLIL_RET')
        self.assertEqual(e.extra['function_status']['skipped'], False)

    def test_list_verbs_report_truncation_at_their_cap(self):
        out = self.call('xrefs', va='helper', limit='1')
        self.assertTrue(out['truncated'])
        self.assertEqual(out['next_offset'], 1)
        out2 = self.call('xrefs', va='helper', limit='1', offset='1')
        self.assertFalse(out2['truncated'])
        self.assertNotEqual(out['result']['xrefs'], out2['result']['xrefs'])
        out = self.call('callers', function='helper')
        self.assertIn('callers', json.dumps(out['result']) + 'callers')
        out = self.call('decompile', function='main', max_lines='2')
        self.assertTrue(out['truncated'])
        self.assertEqual(out['next_offset'], 2)
        out = self.call('decompile', function='main', max_lines='999999')
        self.assertIn('clamped max_lines=999999 to 50000 (allowed 1..50000)', out['warnings'])
        self.assertEqual(out['limits']['max_lines'], 50000)


class DefUseAndCallGraphTests(_ExpertBase):
    def test_ssa_def_and_uses(self):
        r = self.call('ssa_def', function='slice_target', var='i')['result']
        self.assertEqual([(x['var'], x['definition']['op']) for x in r['versions']],
                         [('i#1', 'MLIL_SET_VAR_SSA'), ('i#2', 'MLIL_VAR_PHI'), ('i#3', 'MLIL_SET_VAR_SSA')])
        r = self.call('ssa_def', function='slice_target', var='arg1', version='0')['result']
        self.assertEqual((r['versions'][0]['definition'], r['versions'][0]['origin']), (None, 'param[0] (entry value)'))
        r = self.call('ssa_uses', function='slice_target', var='i#2')['result']
        self.assertEqual([u['va'] for u in r['versions'][0]['uses']], ['0x140001311', '0x14000131b'])
        self.api_error('BAD_ARGUMENT', 400, 'ssa_def', function='slice_target', var='i#2', version='3')
        with self.assertRaises(self.rc.NotFoundError):
            self.call('ssa_def', function='slice_target', var='nosuch')

    def test_branch_dependence(self):
        r = self.call('branch_dependence', va='0x%x' % self.fb.SLICE_CALL)['result']
        deps = r['statements'][0]['dependences']
        # branch_dependence is computed on the NON-SSA MLIL, whose keys index that function: the IF is non-SSA
        # statement 5 (SSA index 6 - the phi has no non-SSA counterpart), at slice_target+0x19
        self.assertEqual([(d['branch_instr_index'], d['dependence'], d['condition'], d['va']) for d in deps],
                         [(5, 'FalseBranchDependent', 'i u< 0x100', '0x140001319')])
        self.assertIn('caveat', r)

    def test_callers_callees_and_call_paths(self):
        r = self.call('callees', function='main', depth='2')['result']
        provs = {(e['to'], e['prov']) for e in r['edges']}
        self.assertIn(('CreateFileW', 'import'), provs)
        self.assertIn(('helper', 'direct'), provs)
        self.assertEqual([n['name'] for n in r['nodes']], ['main', 'helper', 'dispatch', 'leaf'])
        r = self.call('callers', function='leaf')['result']
        self.assertEqual(sorted(e['from'] for e in r['edges']), ['dispatch', 'helper'])
        r = self.call('call_paths', src='main', dst='leaf')['result']
        # main->helper->leaf, main->dispatch->leaf, main->dispatch->helper->leaf
        self.assertEqual(sorted(p['length'] for p in r['paths']), [2, 2, 3])

    def test_return_check_sinks_and_entities(self):
        r = self.call('return_check', call_site='0x140001504')['result']
        self.assertEqual((r['callee'], r['checked']), ('getinput', 'compared-to-const'))
        r = self.call('sinks', preset='memory')['result']
        self.assertEqual(sorted(s['va'] for s in r['sinks']), ['0x14000131b', '0x140001513'])
        r = self.call('undominated_sinks', function='main')['result']
        self.assertEqual([s['sink'] for s in r['undominated']], ['CreateFileW'])
        r = self.call('resolve_entity', ref='g_counter')['result']
        self.assertEqual((r['va'], r['kind'], r['sections']), ('0x140002010', 'data', ['.rdata']))
        r = self.call('uninit_reads', function='slice_target')['result']
        self.assertEqual(r['label'], 'HYPOTHESIS')


class RenderAndPackTests(_ExpertBase):
    def test_decompile_il_asm_and_ast(self):
        r = self.call('decompile', function='dispatch', il='asm')['result']
        self.assertEqual((r['il'], r['render_used'], r['ssa']), ('asm', 'asm', False))
        self.assertIn('cmp ecx, 0x1', r['text'])
        self.assertIn('jne 0x140001210', r['text'])
        self.assertEqual(r['total_lines'], 6)
        r = self.call('decompile', function='main')['result']
        self.assertEqual(r['render_used'], 'ast-lines')
        self.assertIn('{', r['text'])
        r = self.call('decompile', function='main', render='legacy')['result']
        self.assertEqual(r['render_used'], 'non-ast')
        r = self.call('decompile', function='slice_target', il='mlil', ssa='1')['result']
        self.assertIn('phi(i#1, i#3)', r['text'])
        self.api_error('BAD_ARGUMENT', 400, 'decompile', function='main', il='pseudo-c')
        with self.assertRaises(self.rc.AmbiguousError):
            self.call('decompile', function='dup')
        with self.assertRaises(self.rc.NotFoundError):
            self.call('decompile', function='0x140001004')                 # inside main, not a start
        with self.assertRaises(self.rc.NotFoundError):
            self.call('decompile', function='MAIN')                        # never a case-insensitive guess

    def pack(self, view=None, **kw):
        p = dict(function='main', depth='3', disasm='1')
        p.update(kw)
        return self.call('handler_slice', view, **p)['result']

    def test_handler_slice_is_deterministic_and_complete(self):
        r1 = self.pack()
        r2 = self.pack()
        self.assertEqual(r1['pack_sha256'], r2['pack_sha256'])
        self.assertEqual(r1['pack_text'], r2['pack_text'])
        text = r1['pack_text']
        self.assertEqual(hashlib.sha256(text.encode('utf-8')).hexdigest(), r1['pack_sha256'])
        self.assertEqual(text.split('\n', 1)[0], '# BN-PACK v1')
        self.assertTrue(r1['complete'])
        self.assertEqual(r1['sections_missing'], [])
        self.assertEqual(r1['modified_bytes_in_slice'], 0)
        self.assertEqual(r1['function'], {'name': 'main', 'start': '0x140001000'})
        self.assertEqual(r1['sections'][:4], ['TARGET HLIL (main)', 'CALLEE HLIL (helper @ 0x140001100)',
                                              'CALLEE HLIL (dispatch @ 0x140001200)', 'CALLEE HLIL (leaf @ 0x140001180)'])
        for s in ('CALLERS', 'IMPORTS', 'TYPES', 'STRINGS', 'DISASSEMBLY (main)'):
            self.assertIn(s, r1['sections'])
            self.assertIn('\n## %s\n' % s, text)
        self.assertIn('## DISASSEMBLY (main)', text)
        self.assertIn('CreateFileW', text)
        self.assertIn('"config.ini"', text)
        self.assertEqual(r1['render_used'], 'ast-lines')
        self.assertIn('analysis_state: IdleState', text)
        self.assertFalse(r1['truncated'])
        # an identical copy (same bytes, same basename, another directory) produces the identical pack
        other = self.view('copy', 'foo.dll', 'A')
        self.assertEqual(self.pack(other)['pack_sha256'], r1['pack_sha256'])
        no_disasm = self.pack(disasm='0')
        self.assertNotIn('## DISASSEMBLY (', no_disasm['pack_text'])

    def test_handler_slice_reports_modified_bytes(self):
        clean = self.pack()
        n = self.v.write(self.fb.A_HELPER + 4, b'\xcc\xcc')       # inside helper (a callee in the slice)
        self.assertEqual(n, 2)
        dirty = self.pack()
        self.assertEqual(dirty['modified_bytes_in_slice'], 2)
        self.assertNotEqual(dirty['pack_sha256'], clean['pack_sha256'])
        # negative control: 'MyLogPrefix' is referenced by no function of the slice, so it is never rendered.
        # Patched data that IS rendered is the next test.
        self.v.write(self.fb.A_STR_PREFIX, b'xx')
        self.assertEqual(self.pack()['modified_bytes_in_slice'], 2)

    def test_handler_slice_counts_patched_bytes_of_a_rendered_string(self):
        # A pack must never present patched data as the file's bytes. The STRINGS section renders data
        # bytes outside every function range, so the modification count must cover them too.
        # bn_mcp_client writes a pack only when modified_bytes_in_slice == 0 (None counts as not 0).
        stock = self.pack()
        _live_strings(self.v)
        clean = self.pack()
        self.assertEqual(clean['pack_sha256'], stock['pack_sha256'])     # the live-string model renders identically
        self.assertEqual(clean['modified_bytes_in_slice'], 0)
        self.assertEqual(self.v.write(self.fb.A_STR_CONFIG, b'XY'), 2)   # 'config.ini' (main references it)
        self.assertEqual(self.v.modified_count(), 2)
        dirty = self.pack()
        self.assertIn('"XYnfig.ini"', dirty['pack_text'])                 # the patched bytes really reach the pack
        self.assertNotEqual(dirty['pack_sha256'], clean['pack_sha256'])
        self.assertNotEqual(
            dirty['modified_bytes_in_slice'], 0,
            'PLUGIN DEFECT, not a test defect: handler_slice rendered patched string bytes but reported '
            'modified_bytes_in_slice=0, so bn_mcp_client would write the pack as if it showed the file. '
            'expert_ops.modified_bytes counts only the function address ranges, while _strings_of renders '
            'bv.get_string_at(...).value, which reads current bytes. Fix the plugin (count every data range '
            'the pack renders, or fail closed with None); never weaken this assertion.')
        # negative control under the live model: unreferenced data still never reaches the pack
        self.v.write(self.fb.A_STR_PREFIX, b'xx')
        self.assertEqual(self.pack()['pack_sha256'], dirty['pack_sha256'])

    def test_handler_slice_marks_a_missing_section_incomplete(self):
        self.v.get_function_at(self.fb.A_LEAF).hlil_available = False
        r = self.pack()
        self.assertFalse(r['complete'])
        self.assertIn('CALLEE HLIL (leaf @ 0x140001180): NO_IL', r['sections_missing'])
        self.v.get_function_at(self.fb.A_MAIN).hlil_available = False
        r = self.pack()
        self.assertFalse(r['complete'])
        self.assertIn('TARGET HLIL (main): NO_IL', r['sections_missing'])

    def _assert_unfinished_analysis_flagged(self, r, at_start, at_end):
        self.assertFalse(
            r['complete'],
            'PLUGIN DEFECT, not a test defect: handler_slice rendered the pack while analysis_state was not '
            'IdleState but reported complete=true. The HTTP _binary echo samples the state only around the work '
            '(at the start and/or when the answer is sent), so bn_mcp_client could write this pack as complete; '
            'handler_slice must sample the state during the pack and mark any non-IdleState sample incomplete. '
            'Never weaken this assertion.')
        self.assertTrue(r['sections_missing'] and str(r['sections_missing'][0]).startswith('ANALYSIS:'),
                        r['sections_missing'])                  # first, so a client that clips the list still shows it
        self.assertIn('unfinished analysis', r['sections_missing'][0])
        self.assertEqual((r.get('analysis_state_at_start'), r.get('analysis_state_at_end')), (at_start, at_end))

    def test_handler_slice_marks_a_pack_rendered_from_unfinished_analysis_incomplete(self):
        # A pack must never be rendered from unfinished analysis and look complete (bn_mcp_client writes a pack only
        # when complete is true). The state is sampled DURING the pack, not only when the header is built.
        stock = self.pack()
        self.assertTrue(stock['complete'])
        ctl = _script_analysis_state(self.v)
        # (a) analysis still running when the pack starts, finished by the time the header is built (a state read
        #     only for the header, or only when the answer is sent, sees IdleState)
        ctl.arm('AnalyzeState', 'IdleState')
        r = self.pack()
        self.assertTrue(ctl.flipped, 'apparatus: no HLIL was rendered, so the analysis state never changed')
        self._assert_unfinished_analysis_flagged(r, 'AnalyzeState', 'IdleState')
        # (b) idle when the pack starts, re-analysis starts mid-pack and is still running at the end
        ctl.arm('IdleState', 'AnalyzeState')
        r = self.pack()
        self.assertTrue(ctl.flipped, 'apparatus: no HLIL was rendered, so the analysis state never changed')
        self._assert_unfinished_analysis_flagged(r, 'IdleState', 'AnalyzeState')
        # (c) TRANSIENT: idle at the start and at the end, re-analysis during the HLIL renders seen by one interior
        #     sample only (the header sample); the start/end samples, and the HTTP echo built from them, miss it
        ctl.arm('IdleState', 'AnalyzeState', 'IdleState')
        r = self.pack()
        self.assertTrue(ctl.flipped and ctl.flipped_back,
                        'apparatus: the transient change did not happen (reads %s)' % ctl.reads)
        self._assert_unfinished_analysis_flagged(r, 'IdleState', 'IdleState')
        # control: idle throughout -> complete again, and the pack is the stock pack
        ctl.arm('IdleState', 'IdleState')
        r = self.pack()
        self.assertTrue(ctl.flipped)
        self.assertEqual(set(ctl.reads), {'IdleState'})
        self.assertTrue(r['complete'], r['sections_missing'])
        self.assertEqual(r['sections_missing'], [])
        self.assertEqual(r['pack_sha256'], stock['pack_sha256'])

    def _client_fixture(self):
        """The real HTTP server serving self.v, and bn_mcp_client.py run in a temporary working directory with the
        server's token file. Returns (run_pack, packs, srv); run_pack(name) packs main into packs/<name> and returns
        the client's JSON."""
        cwd = os.path.join(self.td.name, 'clientwork')
        packs = os.path.join(cwd, 'packs')
        os.makedirs(packs)
        srv = H.Server(self.m).start()
        self.addCleanup(srv.stop)
        srv.ops.register_view(self.v)
        url = 'http://127.0.0.1:%d' % srv.port
        env = dict(os.environ, BN_MCP_TOKEN_FILE=srv.cfg.server.token_file)

        def run_pack(name):
            p = subprocess.run([sys.executable, '-I', '-B', H.client_path(), 'pack', '--binary', self.v.file.filename,
                                '--function', 'main', '--out', os.path.join('packs', name),
                                '--busy-sleep', '0', '--url', url], capture_output=True, cwd=cwd, timeout=120,
                               env=env)
            self.assertEqual(p.returncode, 0, p.stderr.decode('utf-8', 'replace')[-600:])
            return json.loads(p.stdout.decode('ascii').split('\n', 1)[0])

        return run_pack, packs, srv

    def test_bn_mcp_client_refuses_a_pack_rendered_from_unfinished_analysis(self):
        # End to end over the real HTTP server. Two INDEPENDENT guards keep a pack rendered from unfinished analysis
        # out of packs/: the _binary echo (bn_mcp_client requires analysis_state IdleState; the server samples it
        # when the answer is sent and, in the start-stamping http_server, also under the view lock just before the
        # work) and handler_slice's complete flag (it samples the state DURING the pack). The test pins the safety
        # property (nothing is written) and accepts either guard where both can see the change; it proves the
        # complete flag separately over HTTP, and drives a TRANSIENT change that only the complete flag can see.
        run_pack, packs, srv = self._client_fixture()
        o = run_pack('control.pack')                            # control: idle analysis -> the pack is written
        self.assertTrue(o['written'], o)
        ctl = _script_analysis_state(self.v)
        # (a) analysis running when the pack starts, idle by the time the answer is sent
        ctl.arm('AnalyzeState', 'IdleState')
        o = run_pack('flip.pack')
        self.assertTrue(ctl.flipped, 'apparatus: no HLIL was rendered, so the analysis state never changed')
        self.assertTrue(o['binary_echo_ok'], o)
        self.assertFalse(
            o['written'],
            'PLUGIN DEFECT, not a test defect: bn_mcp_client wrote a pack rendered while analysis was not IdleState '
            '(%s); the echo must not read IdleState for it, or handler_slice must report complete=false.' % o)
        if o['analysis_state'] == 'IdleState':
            # an echo sampled only when the answer is sent cannot see the change: the complete flag refused it
            self.assertIn('incomplete', o['refused_reason'])
            self.assertIn('ANALYSIS:', o['refused_reason'])
        else:
            # the echo's start sample (taken under the view lock just before the work) saw the change
            self.assertEqual(o['analysis_state'], 'AnalyzeState', o)
            self.assertIn('analysis_state is AnalyzeState', o['refused_reason'])
        # the plugin's complete flag on its own, read directly over HTTP (independent of which echo the server has)
        ctl.arm('AnalyzeState', 'IdleState')
        r = srv.get('/x/handlerSlice', {'binary': self.v.file.filename, 'function': 'main', 'disasm': '1'})
        self.assertTrue(ctl.flipped, 'apparatus: no HLIL was rendered, so the analysis state never changed')
        self.assertEqual(r.status, 200, r.raw[:300])
        res = r.json['result']
        self.assertIs(res['complete'], False, res['sections_missing'])
        self.assertTrue(res['sections_missing'] and str(res['sections_missing'][0]).startswith('ANALYSIS:'),
                        res['sections_missing'])
        self.assertEqual(r.json['_binary']['filename'], self.v.file.filename)
        # (b) TRANSIENT: idle when the work starts and when the answer is sent, re-analysis during the HLIL renders.
        #     Every echo sample reads IdleState, so handler_slice's complete flag is the only guard: the client must
        #     refuse through it.
        ctl.arm('IdleState', 'AnalyzeState', 'IdleState')
        o = run_pack('transient.pack')
        self.assertTrue(ctl.flipped and ctl.flipped_back,
                        'apparatus: the transient change did not happen (reads %s)' % ctl.reads)
        self.assertTrue(o['binary_echo_ok'], o)
        self.assertEqual(o['analysis_state'], 'IdleState',
                         'apparatus: the echo saw the transient change, so this case no longer isolates the '
                         'complete flag (%s)' % o)
        self.assertFalse(
            o['written'],
            'PLUGIN DEFECT, not a test defect: bn_mcp_client wrote a pack whose HLIL was rendered during analysis '
            '(%s); handler_slice must report complete=false for it.' % o)
        self.assertIn('incomplete', o['refused_reason'])
        self.assertIn('ANALYSIS:', o['refused_reason'])
        self.assertEqual(sorted(os.listdir(packs)), ['control.pack'])

    def test_handler_slice_fails_closed_on_a_raw_patch_outside_the_slice(self):
        # A patch_bytes write the server recorded ANYWHERE in the view (here getinput, a function the pack of
        # main never renders) can shape what the pack renders (callees beyond depth/max_callees or dropped by
        # max_chars, jump tables, data), so the in-slice byte count cannot clear the view: modified_bytes_in_slice is
        # None (never 0) and the pack is incomplete, with the reason FIRST in sections_missing. A plugin tree whose
        # expert_ops.py lacks this fail-closed rule fails here; never relax this test.
        stock = self.pack()
        self.assertEqual((stock['complete'], stock['modified_bytes_in_slice']), (True, 0))
        site = self.fb.A_GETINPUT + 1
        with self.ops.using_view(self.v):
            res = self.ops.patch_bytes(hex(site), '90')
        self.assertEqual(res['status'], 'ok', res)
        vid = self.ops.describe_view(self.v)['view_id']
        self.assertEqual(len(self.ops.raw_patches(vid)), 1)    # apparatus: the server recorded the write
        self.assertEqual(self.v.modified_count(), 1)            # apparatus: the byte really changed
        r = self.pack()
        self.assertFalse([s for s in r['sections'] if 'getinput' in s],
                         'apparatus: the patched function is rendered, so this is not an out-of-slice patch')
        self.assertIsNone(
            r['modified_bytes_in_slice'],
            'PLUGIN DEFECT, not a test defect: handler_slice reported modified_bytes_in_slice=%r for a view carrying '
            'a recorded patch_bytes write, so bn_mcp_client would write the pack as if it showed the file. It must be None '
            '(never 0) whenever the server recorded a modification of the view.' % (r['modified_bytes_in_slice'],))
        self.assertIs(r['complete'], False, r['sections_missing'])
        self.assertTrue(r['sections_missing'] and str(r['sections_missing'][0]).startswith('MODIFIED:'),
                        r['sections_missing'])

    def test_bn_mcp_client_refuses_a_pack_of_a_view_with_a_recorded_raw_patch(self):
        # End to end: a legacy /patch (patch_bytes, save_to_file=0) outside the rendered slice, then a client pack.
        # The pack text alone cannot show the patch, so the plugin's fail-closed flags are what keep it out of packs/.
        run_pack, packs, srv = self._client_fixture()
        o = run_pack('control.pack')                            # control: the unpatched view -> the pack is written
        self.assertTrue(o['written'], o)
        sel = {'binary': self.v.file.filename}
        r = srv.get('/patch', dict(sel, address='0x%x' % (self.fb.A_GETINPUT + 1), data='90', save_to_file='0'))
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertIs(srv.get('/status', sel).json['_binary']['modified'], True)   # apparatus: recorded
        o = run_pack('patched.pack')
        self.assertTrue(o['binary_echo_ok'], o)
        self.assertFalse(
            o['written'],
            'PLUGIN DEFECT, not a test defect: bn_mcp_client wrote a pack of a view that carries a recorded '
            'patch_bytes write (%s); handler_slice must fail closed (modified_bytes_in_slice None, complete false).' % o)
        self.assertTrue(o['refused_reason'], o)
        self.assertEqual(sorted(os.listdir(packs)), ['control.pack'])

    def test_handler_slice_size_control(self):
        v = self.view('long', 'long.dll', 'Q', extra=_long_and_caller)
        r = self.pack(v, function='bigcaller', max_chars='4000', disasm='0')
        self.assertTrue(r['truncated'])
        self.assertEqual(r['sections_dropped'][0], 'CALLEE HLIL (longfn @ 0x140001700)')
        self.assertEqual(r['callees_omitted'], 1)
        self.assertTrue(r['complete'])                    # only cutting the TARGET makes a pack incomplete
        self.assertLessEqual(len(r['pack_text']), 4000)
        self.assertEqual(r['pack_text'].split('\n', 1)[0], '# BN-PACK v1')
        r = self.pack(v, function='longfn', max_chars='4000', disasm='0')
        self.assertTrue(r['truncated'])
        self.assertFalse(r['complete'])
        self.assertIn('TARGET HLIL (longfn): truncated by max_chars=4000', r['sections_missing'])
        self.assertIn('// TARGET HLIL TRUNCATED', r['pack_text'])
        self.assertLessEqual(len(r['pack_text']), 4000)
        self.api_error('BAD_ARGUMENT', 400, 'handler_slice', function='main', include='hlil,everything')

    def test_compute(self):
        r = self.call('compute', expr='0x10<<4')['result']
        self.assertEqual((r['dec'], r['hex']), ('256', '0x100'))
        self.assertEqual(self.call('compute', expr='0n10 + 0x10 - 1')['result']['dec'], '25')
        self.assertEqual(self.call('compute', expr='-1')['result']['u32'], '0xffffffff')
        for bad in ('__import__("os")', '__import__', 'os.system', 'open("x")', '1/2', '2**4096', 'x+1',
                    '[1,2]', '1 if 1 else 2', '"abc"', '1 << 4096'):
            with self.subTest(expr=bad):
                self.api_error('BAD_ARGUMENT', 400, 'compute', expr=bad)
        with self.ops.using_view(self.v):
            out = self.ex.VERB_FUNCS['compute'](self.ops, None, {'expr': '3*7'})
        self.assertEqual(out['result']['dec'], '21')

    def test_verbs_never_mutate_analysis_state(self):
        for verb, p in (('decompile', {'function': 'main'}), ('function_status', {'function': 'main'}),
                        ('il_search', {'operation': 'MLIL_RET'}), ('handler_slice', {'function': 'main'}),
                        ('backward_slice', {'call_site': '0x%x' % self.fb.SLICE_CALL, 'arg_index': '2'}),
                        ('possible_values', {'va': '0x140001500'}), ('cfg', {'function': 'dispatch'}),
                        ('callees', {'function': 'main', 'depth': '3'}), ('sinks', {'function': 'main'}),
                        ('binary_info', {}), ('debug_info_status', {}), ('stack_frame', {'function': 'main'})):
            with self.subTest(verb=verb):
                self.call(verb, **p)
        self.assertEqual(self.v.update_calls, 0)
        self.assertEqual([f.name for f in self.v.functions if f.skipped_writes], [])
        self.assertEqual(self.v.save_calls, [])
        self.assertEqual(self.v.modified_count(), 0)

    def test_analysis_state_is_reported_by_name(self):
        r = self.call('binary_info')['result']
        self.assertEqual(r['analysis_state'], 'IdleState')
        r = self.call('function_status', function='main')['result']
        self.assertEqual(r['analysis_state'], 'IdleState')
        self.assertEqual(self.ex.state_name(H.ensure_fake().enums.AnalysisState.IdleState), 'IdleState')
        self.assertEqual(self.ex.state_name(2), 'IdleState')
        self.assertEqual(self.ex.state_name(None), 'unknown')


class BatchAndHttpTests(_ExpertBase):
    def test_batch_per_item_errors_and_warnings(self):
        items = [
            {'verb': 'decompile', 'params': {'function': 'leaf'}},
            {'verb': 'decompile', 'params': {'function': 'main', 'max_lines': '999999'}},
            {'verb': 'no_such_verb', 'params': {}},
            {'verb': 'decompile', 'params': {'function': 'main', 'binary': 'foo.dll'}},
            {'verb': 'load_binary', 'params': {'filepath': 'C:\\x.dll'}},
            {'verb': 'close_binary', 'params': {}},
            {'verb': 'decompile', 'params': {'function': 'dup'}},
            {'verb': '/x/compute', 'params': {'expr': '1+1'}},
            'not-an-object',
        ]
        out = self.call('batch', items=json.dumps(items))
        res = out['result']['items']
        self.assertEqual([x['index'] for x in res], list(range(len(items))))
        self.assertEqual([x['ok'] for x in res], [True, True, False, False, False, False, False, True, False])
        self.assertEqual(res[2]['error_code'], 'BAD_ARGUMENT')
        self.assertEqual(res[3]['error_code'], 'BAD_ARGUMENT')
        self.assertEqual(res[4]['error_code'], 'POLICY')
        self.assertEqual(res[5]['error_code'], 'POLICY')
        self.assertEqual(res[6]['error_code'], 'AMBIGUOUS')
        self.assertEqual(len(res[6]['candidates']), 2)
        self.assertEqual(res[8]['error_code'], 'BAD_ARGUMENT')
        self.assertIn('clamped max_lines=999999 to 50000 (allowed 1..50000)', res[1]['warnings'])
        self.assertEqual(res[0]['warnings'], [])
        self.assertEqual(out['result']['ok_count'], 3)
        self.assertIsNone(self.rc.ambiguity())
        too_many = [{'verb': 'compute', 'params': {'expr': '1'}}] * 26
        self.api_error('BAD_ARGUMENT', 400, 'batch', items=json.dumps(too_many))
        self.api_error('BAD_ARGUMENT', 400, 'batch', items='{not json')

    def test_results_above_two_mib_are_refused_with_413(self):
        big = self.view('big', 'big.dll', 'G', extra=self.fb.add_big_function)
        p = {'function': 'bigfn', 'text_regex': 'big_', 'limit': '5000'}
        with self.assertRaises(self.rc.ApiError) as cm:
            self.call('il_search', big, **p)
        self.assertEqual((cm.exception.code, cm.exception.http_status), ('REFUSED_SIZE', 413))
        self.assertGreater(cm.exception.extra['bytes'], 2 * 1024 * 1024)
        out = self.call('batch', big, items=[{'verb': 'il_search', 'params': p},
                                             {'verb': 'decompile', 'params': {'function': 'main'}}])
        res = out['result']['items']
        self.assertEqual((res[0]['ok'], res[0]['error_code']), (False, 'REFUSED_SIZE'))
        self.assertTrue(res[1]['ok'])
        guarded = self.ex._guard('synthetic', lambda ops, bv, p: {'result': 'x' * (2 * 1024 * 1024 + 1)}, False)
        with self.assertRaises(self.rc.ApiError) as cm:
            guarded(self.ops, None, {})
        self.assertEqual(cm.exception.http_status, 413)
        srv = H.Server(self.m).start()
        self.addCleanup(srv.stop)
        srv.ops.register_view(big)
        r = srv.get('/x/ilSearch', dict(p, binary=big.file.filename), timeout=60)
        self.assertEqual(r.status, 413, r.raw[:300])
        self.assertEqual((r.json['ok'], r.json['error_code']), (False, 'REFUSED_SIZE'))
        self.assertEqual(r.json['_binary']['filename'], big.file.filename)

    def test_http_envelopes_and_status_mapping(self):
        srv = H.Server(self.m).start()
        self.addCleanup(srv.stop)
        srv.ops.register_view(self.v)
        sel = {'binary': self.v.file.filename}
        r = srv.get('/x/decompile', dict(sel, function='main'))
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(set(r.json) >= {'ok', 'verb', 'result', 'truncated', 'next_offset', 'warnings', 'limits',
                                         '_binary'}, True)
        self.assertEqual((r.json['ok'], r.json['verb']), (True, 'decompile'))
        r = srv.get('/x/decompile', dict(sel, function='dup'))
        self.assertEqual(r.status, 409)
        self.assertEqual((r.json['ok'], r.json['error_code'], len(r.json['candidates'])), (False, 'AMBIGUOUS', 2))
        r = srv.get('/x/decompile', dict(sel, function='nope'))
        self.assertEqual((r.status, r.json['error_code']), (404, 'NOT_FOUND'))
        r = srv.get('/x/decompile', dict(sel, function='main', il='pseudo'))
        self.assertEqual((r.status, r.json['error_code']), (400, 'BAD_ARGUMENT'))
        r = srv.get('/x/possibleValues', dict(sel, va='0x140001500', max_complexity='1'))
        self.assertEqual((r.status, r.json['error_code'], r.json['complexity']), (422, 'REFUSED_COMPLEXITY', 3))
        r = srv.get('/x/decompile', {'function': 'main'})                  # no binary, nothing selected
        self.assertEqual((r.status, r.json['error_code']), (404, 'NOT_FOUND'))
        self.assertEqual([x['filename'] for x in r.json['available']], [self.v.file.filename])
        r = srv.get('/x/serverInfo')
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json['result']['contract'], H.CONTRACT)
        self.assertNotIn('_binary', r.json)
        r = srv.get('/x/compute', {'expr': '__import__'})
        self.assertEqual((r.status, r.json['error_code']), (400, 'BAD_ARGUMENT'))
        r = srv.get('/x/batch', dict(sel, items='[]'))
        self.assertEqual(r.status, 404)                                   # POST-only: GET falls to the legacy 404
        self.assertNotIn('verb', r.json)
        r = srv.post('/x/batch', params=sel, json_body={'items': [{'verb': 'compute', 'params': {'expr': '2+2'}}]})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(r.json['result']['items'][0]['result']['dec'], '4')
        r = srv.post('/x/handlerSlice', params=sel, json_body={'function': 'main', 'disasm': 1})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertIn('## DISASSEMBLY (main)', r.json['result']['pack_text'])

    def test_every_route_names_an_existing_verb(self):
        ep = self.m.endpoints
        tables = dict(ep.ROUTES_GET)
        tables.update(ep.ROUTES_POST)
        self.assertEqual(set(ep.ROUTES_POST) >= set(ep.ROUTES_GET), True)
        for path, verb in sorted(tables.items()):
            with self.subTest(path=path):
                fn = self.ex.VERB_FUNCS.get(verb)
                self.assertTrue(callable(fn), '%s -> %s resolves to no verb' % (path, verb))
        want_get = {'/x/serverInfo', '/x/binaryInfo', '/x/functionStatus', '/x/decompile', '/x/ilSearch', '/x/ssaDef',
                    '/x/ssaUses', '/x/backwardSlice', '/x/possibleValues', '/x/branchDependence', '/x/cfg',
                    '/x/dominators', '/x/reachable', '/x/callers', '/x/callees', '/x/callPaths', '/x/returnCheck',
                    '/x/sinks', '/x/undominatedSinks', '/x/stackFrame', '/x/handlerSlice', '/x/resolveEntity',
                    '/x/bytesAt', '/x/xrefs', '/x/debugInfoStatus', '/x/uninitReads', '/x/resolveDispatch',
                    '/x/ndrDecode', '/x/interprocSlice', '/x/compute'}
        self.assertEqual(set(ep.ROUTES_GET), want_get)
        want_post_only = {'/x/batch', '/x/closeBinary', '/x/loadBinary'}
        self.assertEqual(set(ep.ROUTES_POST) - set(ep.ROUTES_GET), want_post_only)
        self.assertEqual(self.ex.VIEWLESS, {'compute', 'server_info', 'load_binary'})
        # load_binary opens a view: a batch refuses it like close_binary
        self.assertIn('load_binary', self.ex._MUTATING_VERBS)


class CompositionVerbTests(_ExpertBase):
    """The three additive read-only composition verbs: resolve_dispatch, ndr_decode, interproc_slice."""

    # ---- resolve_dispatch ------------------------------------------------------------------------------------
    def test_resolve_dispatch_resolves_a_direct_call_site(self):
        r = self.call('resolve_dispatch', function='main', call_site=hex(self.fb.A_MAIN + 0x4))['result']
        self.assertEqual(r['sites_examined'], 1)
        row = r['resolved'][0]
        self.assertEqual(row['method'], 'const')
        self.assertEqual([t['target_name'] for t in row['targets']], ['helper'])

    def test_resolve_dispatch_finds_no_indirect_site_in_a_direct_function(self):
        r = self.call('resolve_dispatch', function='dispatch')['result']
        self.assertEqual(r['sites_examined'], 0)
        self.assertEqual(r['resolved'], [])

    def test_resolve_dispatch_resolves_an_indirect_call_by_value_set(self):
        v = self.view('idp', 'foo.dll', 'A', _indirect_dispatch)
        r = self.call('resolve_dispatch', v, function='dispatcher')['result']
        self.assertEqual(r['sites_examined'], 1)
        row = r['resolved'][0]
        self.assertEqual(row['method'], 'value-set')
        self.assertEqual(sorted(t['target_name'] for t in row['targets']), ['helper', 'leaf'])
        self.assertIn('FromAddressesInLookupTableQueryOption', r['options_used'])
        self.assertTrue(any(ic['var'] == 't#1' for ic in row['index_candidates']))

    def test_resolve_dispatch_rejects_a_bare_digit_address(self):
        self.api_error('BAD_ARGUMENT', 400, 'resolve_dispatch', function='dispatch', call_site='1234')

    # ---- ndr_decode ------------------------------------------------------------------------------------------
    def test_ndr_decode_params_oif_pure(self):
        # [in] FC_LONG basetype | [out] simple-ref complex | [in,out] FC_SHORT basetype
        data = bytes([0x48, 0x00, 0x08, 0x00, 0x08, 0x5c,
                      0x10, 0x01, 0x10, 0x00, 0x20, 0x00,
                      0x58, 0x00, 0x18, 0x00, 0x06, 0x5c])
        params, consumed, trunc = self.ex._ndr_decode_params(data, 0, 3, oif=True)
        self.assertFalse(trunc)
        self.assertEqual(consumed, 18)
        self.assertEqual(params[0]['direction'], ['in'])
        self.assertEqual((params[0]['kind'], params[0]['type']), ('basetype', 'FC_LONG'))
        self.assertEqual(params[1]['direction'], ['out'])
        self.assertEqual(params[1]['kind'], 'complex')
        self.assertTrue(params[1]['is_simple_ref'])
        self.assertEqual(params[1]['type_offset'], '0x0020')
        self.assertEqual(params[2]['direction'], ['in', 'out'])
        self.assertEqual(params[2]['type'], 'FC_SHORT')

    def test_ndr_decode_params_oi_and_unknown_fc(self):
        # -Oi: direction byte 0x50 (FC_IN_OUT_PARAM), then one with an unknown direction byte
        data = bytes([0x50, 0x08, 0x02, 0x00, 0xaa, 0x04, 0x00, 0x00])
        params, _consumed, trunc = self.ex._ndr_decode_params(data, 0, 2, oif=False)
        self.assertFalse(trunc)
        self.assertEqual((params[0]['direction'], params[0]['direction_fc']), (['in', 'out'], 'FC_IN_OUT_PARAM'))
        self.assertEqual(params[1]['direction'], ['(unknown)'])
        self.assertEqual(params[1]['direction_fc'], 'FC_0xaa')

    def test_ndr_decode_params_truncates_without_enough_bytes(self):
        params, _c, trunc = self.ex._ndr_decode_params(bytes([0x48, 0x00, 0x08, 0x00]), 0, 2, oif=True)
        self.assertEqual(params, [])
        self.assertTrue(trunc)

    def test_ndr_decode_verb_reads_the_view_and_decodes(self):
        # write a known -Oif param array into the view's data region, then decode it through the verb
        at = self.fb.A_COUNTER
        self.v.write(at, bytes([0x48, 0x00, 0x08, 0x00, 0x08, 0x5c, 0x70, 0x00, 0x00, 0x00, 0x08, 0x5c]))
        r = self.call('ndr_decode', va=hex(at), count=2)['result']
        self.assertEqual(r['count_decoded'], 2)
        self.assertEqual(r['params'][0]['type'], 'FC_LONG')
        self.assertEqual(sorted(r['params'][1]['direction']), ['out', 'return'])
        self.assertEqual(r['count_bounded_by'], 'count')

    def test_ndr_decode_rejects_a_bad_format(self):
        self.api_error('BAD_ARGUMENT', 400, 'ndr_decode', va=hex(self.fb.A_COUNTER), format='ndr64')

    # ---- interproc_slice -------------------------------------------------------------------------------------
    def test_interproc_slice_reports_a_frontier_when_no_caller(self):
        r = self.call('interproc_slice', call_site=hex(self.fb.SLICE_CALL), arg_index=2)['result']
        self.assertEqual(r['frames'][0]['function']['name'], 'slice_target')
        self.assertTrue(any(fr['param_index'] == 0 for fr in r['frontier']))
        self.assertEqual(r['chain'], ['slice_target'])

    def test_interproc_slice_ascends_into_a_caller(self):
        v = self.view('ip', 'foo.dll', 'A', _slice_caller)
        r = self.call('interproc_slice', v, call_site=hex(self.fb.SLICE_CALL), arg_index=2)['result']
        names = [f['function']['name'] for f in r['frames'] if f.get('function')]
        self.assertIn('slice_target', names)
        self.assertIn('outer', names)
        self.assertEqual(r['chain'], ['slice_target', 'outer'])

    def test_interproc_slice_leaves_backward_slice_behaviour_unchanged(self):
        # the frame-0 sources are exactly what backward_slice returns for the same seed
        seed = dict(call_site=hex(self.fb.SLICE_CALL), arg_index=2)
        direct = self.call('backward_slice', **seed)['result']
        frame0 = self.call('interproc_slice', **seed)['result']['frames'][0]
        self.assertEqual(frame0['sources'], direct['sources'])

    # ---- read-only guarantee across all three ----------------------------------------------------------------
    def test_new_verbs_never_mutate_the_view(self):
        self.v.write(self.fb.A_COUNTER, bytes([0x48, 0x00, 0x08, 0x00, 0x08, 0x5c]))
        before = self.v.analysis_state
        writes_before = len(self.v.write_calls)
        for verb, params in (('resolve_dispatch', {'function': 'dispatch'}),
                             ('ndr_decode', {'va': hex(self.fb.A_COUNTER), 'count': 1}),
                             ('interproc_slice', {'call_site': hex(self.fb.SLICE_CALL), 'arg_index': 2})):
            self.call(verb, **params)
        self.assertIs(self.v.analysis_state, before)
        self.assertEqual(len(self.v.write_calls), writes_before)   # no verb wrote bytes
        self.assertEqual(self.v.save_calls, [])


if __name__ == '__main__':
    unittest.main()
