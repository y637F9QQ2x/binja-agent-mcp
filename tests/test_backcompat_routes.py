# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Backward compatibility of every legacy HTTP route against the upstream baseline.

The baseline is a checkout of the upstream plugin at tag v1.1.0, named by BN_MCP_TEST_BASELINE (loaded by
run_tests.baseline_modules() as 'bnmcp_base'; without it the baseline tests are skipped). Every legacy (method, path)
pair is DISCOVERED from the baseline server source, so a route added to or removed from the table is noticed. Both
servers get byte-identical fake views and the same request sequence; the plugin under test must answer every route
with the same HTTP status and a JSON key set that is a SUPERSET of the baseline's.
"""

import os
import re
import sys
import tempfile
import unittest

import run_tests as H

# Legacy request table: (method, path, params). Read-only routes first, then the mutating ones (same order for both
# servers), /load last. save_to_file=0 keeps the like-for-like comparison of /patch (the save policy change is
# tested separately below).
LEGACY_REQUESTS = [
    ('GET', '/status', {}),
    ('GET', '/functions', {}),
    ('GET', '/methods', {'offset': '0', 'limit': '5'}),
    ('GET', '/classes', {}),
    ('GET', '/segments', {}),
    ('GET', '/imports', {}),
    ('GET', '/binaries', {}),
    ('GET', '/views', {}),
    ('GET', '/exports', {}),
    ('GET', '/sections', {}),
    ('GET', '/entryPoints', {}),
    ('GET', '/namespaces', {}),
    ('GET', '/data', {}),
    ('GET', '/localTypes', {}),
    ('GET', '/searchTypes', {'query': 'My'}),
    ('GET', '/strings', {}),
    ('GET', '/allStrings', {}),
    ('GET', '/hexdump', {'address': '0x140002000', 'length': '32'}),
    ('GET', '/hexdumpByName', {'name': 'g_counter'}),
    ('GET', '/getDataDecl', {'name': 'g_counter'}),
    ('GET', '/strings/filter', {'filter': 'conf'}),
    ('GET', '/searchFunctions', {'query': 'help'}),
    ('GET', '/decompile', {'name': 'main'}),
    ('GET', '/decompile', {'name': 'no_such_function'}),
    ('GET', '/assembly', {'name': 'dispatch'}),
    ('GET', '/il', {'name': 'main', 'view': 'mlil'}),
    ('GET', '/il', {'address': '0x140001100', 'view': 'llil'}),
    ('GET', '/functionAt', {'address': '0x140001004'}),
    ('GET', '/getUserDefinedType', {'name': 'MyStruct'}),
    ('GET', '/comment', {'address': '0x140001000'}),
    ('GET', '/comment/function', {'name': 'main'}),
    ('GET', '/getComment', {'address': '0x140001000'}),
    ('GET', '/getFunctionComment', {'name': 'main'}),
    ('GET', '/platforms', {}),
    ('GET', '/getXrefsTo', {'address': '0x140001100'}),
    ('GET', '/getXrefsToField', {'struct': 'MyStruct', 'field': 'a'}),
    ('GET', '/getXrefsToStruct', {'name': 'MyStruct'}),
    ('GET', '/getXrefsToType', {'name': 'MyStruct'}),
    ('GET', '/getTypeInfo', {'name': 'MyStruct'}),
    ('GET', '/getXrefsToEnum', {'name': 'MyEnum'}),
    ('GET', '/getXrefsToUnion', {'name': 'MyUnion'}),
    ('GET', '/formatValue', {'address': '0x140002010', 'text': '7', 'size': '4'}),
    ('GET', '/convertNumber', {'text': '0x10'}),
    ('GET', '/selectBinary', {'view': 'foo.dll'}),
    ('GET', '/makeFunctionAt', {'address': '0x140001180'}),
    ('GET', '/setFunctionPrototype', {'address': '0x140001180', 'prototype': 'int64_t leaf(void)'}),
    ('GET', '/setLocalVariableType', {'functionAddress': '0x140001100', 'variableName': 'arg1', 'newType': 'int32_t'}),
    ('GET', '/retypeVariable', {'functionName': 'helper', 'variableName': 'arg1', 'type': 'int32_t'}),
    ('GET', '/renameVariable', {'functionName': 'helper', 'variableName': 'arg1', 'newName': 'count'}),
    ('GET', '/renameVariables', {'functionName': 'helper', 'pairs': 'count:arg1'}),
    ('GET', '/defineTypes', {'cCode': 'struct Defined { int a; };'}),
    ('GET', '/declareCType', {'declaration': 'struct Declared { int b; };'}),
    ('GET', '/patch', {'address': '0x140002040', 'data': '9090', 'save_to_file': '0'}),
    ('GET', '/patchBytes', {'address': '0x140002042', 'data': 'c3', 'save_to_file': 'false'}),
    ('POST', '/rename/function', {'oldName': 'leaf', 'newName': 'leaf2'}),
    ('POST', '/renameFunction', {'oldName': 'leaf2', 'newName': 'leaf3'}),
    ('POST', '/rename/data', {'address': '0x140002010', 'newName': 'g_counter2'}),
    ('POST', '/renameData', {'address': '0x140002010', 'newName': 'g_counter3'}),
    ('POST', '/comment', {'address': '0x140001000', 'comment': 'c1'}),
    ('POST', '/comment/function', {'name': 'main', 'comment': 'fc'}),
    ('POST', '/getComment', {'address': '0x140001000'}),
    ('POST', '/getFunctionComment', {'name': 'main'}),
    ('POST', '/patch', {'address': '0x140002050', 'data': '41', 'save_to_file': '0'}),
    ('POST', '/patchBytes', {'address': '0x140002051', 'data': '42', 'save_to_file': 'false'}),
    ('POST', '/load', {'filepath': '<LOADFILE>'}),
]


def discover_baseline_routes():
    """{(METHOD, path)} handled by the baseline server (parsed from its source: do_GET before do_POST)."""
    if not H.BASELINE_DIR or not os.path.isdir(H.BASELINE_DIR):
        raise unittest.SkipTest('the upstream v1.1.0 baseline is not available (set BN_MCP_TEST_BASELINE)')
    src_path = os.path.join(H.BASELINE_DIR, 'plugin', 'server', 'http_server.py')
    with open(src_path, encoding='utf-8') as f:
        src = f.read()
    cut = src.index('def do_POST')
    out = set()
    for m in re.finditer(r'path == "(/[^"]*)"', src):
        out.add(('GET' if m.start() < cut else 'POST', m.group(1)))
    return out


def _long_function(view):
    fb = H.fake_bv()
    start = fb.IMAGE_BASE + 0x1700
    insns = [fb.Insn(start + k, 1, 'nop', 'int64_t long_line_%04d = some_long_expression_value_%04d' % (k, k))
             for k in range(0x0f0)]
    f = fb.Function(view, 'longfn', start, insns)
    view.add_fake_function(f)


class BackcompatTests(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.fb = H.fake_bv()
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-compat-')
        self.addCleanup(self.td.cleanup)
        self.views = []

    def view(self, sub, basename='foo.dll', tag='A', extra=None):
        v = H.make_view(os.path.join(self.td.name, sub), basename, tag, 0.0, extra)
        self.views.append(v)
        return v

    def started(self, mods, **cfg):
        s = H.Server(mods, **cfg)
        s.start()
        self.addCleanup(s.stop)
        return s

    def _req(self, srv, method, path, params, load_file):
        p = {k: (load_file if v == '<LOADFILE>' else v) for k, v in params.items()}
        if method == 'GET':
            return srv.get(path, p, timeout=60)
        return srv.post(path, json_body=p, timeout=60)

    def test_every_baseline_route_is_in_the_table(self):
        want = discover_baseline_routes()
        have = {(mth, p) for (mth, p, _q) in LEGACY_REQUESTS}
        missing = sorted(want - have)
        self.assertEqual(missing, [], 'legacy routes without a backcompat request: %s' % missing)
        self.assertGreaterEqual(len(want), 60)

    def test_legacy_routes_keep_status_and_a_superset_of_response_keys(self):
        base = H.baseline_modules()
        old_v = self.view('old', 'foo.dll', 'A')
        new_v = self.view('new', 'foo.dll', 'A')
        old = self.started(base)
        new = self.started(self.m)
        # register BEFORE selecting: the baseline's setter prunes unregistered views and would clear the selection
        old.ops.register_view(old_v)
        old.ops.current_view = old_v
        new.ops.register_view(new_v)
        new.ops.current_view = new_v
        self.assertIs(old.ops.current_view, old_v)
        load_old = self.fb.make_standard_file(os.path.join(self.td.name, 'ld_old'), 'loaded.dll', 'L')
        load_new = self.fb.make_standard_file(os.path.join(self.td.name, 'ld_new'), 'loaded.dll', 'L')
        problems = []
        compared = 0
        for (method, path, params) in LEGACY_REQUESTS:
            ro = self._req(old, method, path, params, load_old)
            rn = self._req(new, method, path, params, load_new)
            tag = '%s %s %s' % (method, path, params)
            if rn.status != ro.status:
                problems.append('%s: status %s (baseline %s): %s' % (tag, rn.status, ro.status, rn.raw[:200]))
                continue
            if isinstance(ro.json, dict):
                if not isinstance(rn.json, dict):
                    problems.append('%s: the plugin under test answered non-JSON' % tag)
                    continue
                lost = sorted(set(ro.json) - set(rn.json))
                if lost:
                    problems.append('%s: keys lost %s' % (tag, lost))
                compared += 1
            elif ro.json is None:
                ct_o = ro.headers.get('content-type', '')
                ct_n = rn.headers.get('content-type', '')
                if ct_o.split(';')[0] != ct_n.split(';')[0]:
                    problems.append('%s: content-type %s (baseline %s)' % (tag, ct_n, ct_o))
        self.assertEqual(problems, [])
        self.assertGreaterEqual(compared, 50)
        self.assertEqual(new_v.save_calls, [])
        self.assertEqual(old_v.save_calls, [])

    def test_legacy_decompile_il_assembly_text_is_byte_identical_and_uncapped(self):
        base = H.baseline_modules()
        old_v = self.view('old', 'foo.dll', 'A', _long_function)
        new_v = self.view('new', 'foo.dll', 'A', _long_function)
        old = self.started(base)
        new = self.started(self.m)
        old.ops.register_view(old_v)
        old.ops.current_view = old_v
        new.ops.current_view = new_v
        for path, params, key in (('/decompile', {'name': 'longfn'}, 'decompiled'),
                                  ('/decompile', {'name': 'main'}, 'decompiled'),
                                  ('/il', {'name': 'slice_target', 'view': 'mlil', 'ssa': '1'}, 'il'),
                                  ('/il', {'name': 'longfn', 'view': 'hlil'}, 'il'),
                                  ('/assembly', {'name': 'dispatch'}, 'assembly')):
            with self.subTest(path=path, params=params):
                ro = old.get(path, params)
                rn = new.get(path, params)
                rl = new.get(path, dict(params, render='legacy'))
                self.assertEqual((ro.status, rn.status, rl.status), (200, 200, 200))
                self.assertEqual(rn.json[key], ro.json[key])
                self.assertEqual(rl.json[key], ro.json[key])
                self.assertFalse(rn.json['truncated'])
                self.assertIsNone(rn.json['next_line_offset'])
                self.assertEqual(rn.json['returned_lines'], rn.json['total_lines'])
                self.assertEqual(rn.json['total_lines'], len(ro.json[key].split('\n')))
        long_text = new.get('/decompile', {'name': 'longfn'}).json['decompiled']
        self.assertGreater(len(long_text), 15000)
        # an explicit cap pages on a line boundary
        r = new.get('/decompile', {'name': 'longfn', 'max_lines': '10'})
        self.assertTrue(r.json['truncated'])
        self.assertEqual((r.json['returned_lines'], r.json['next_line_offset']), (10, 10))
        self.assertEqual(r.json['decompiled'].split('\n'), long_text.split('\n')[:10])
        r2 = new.get('/decompile', {'name': 'longfn', 'line_offset': '10', 'max_lines': '5'})
        self.assertEqual(r2.json['decompiled'].split('\n'), long_text.split('\n')[10:15])
        # render=ast is the brace-structured AST rendering
        ra = new.get('/decompile', {'name': 'main', 'render': 'ast'})
        self.assertIn('{', ra.json['decompiled'])
        self.assertNotIn('{', new.get('/decompile', {'name': 'main'}).json['decompiled'])

    def test_omitted_binary_uses_the_global_view_and_select_binary_still_selects(self):
        a = self.view('a', 'foo.dll', 'A')
        b = self.view('b', 'bar.dll', 'B')
        srv = self.started(self.m)
        srv.ops.register_view(a)
        srv.ops.register_view(b)
        r = srv.get('/selectBinary', {'binary': 'bar.dll'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(r.json['status'], 'ok')
        self.assertNotIn('_binary', r.json)              # /selectBinary is scope-exempt: `binary` is the TARGET
        self.assertIs(srv.ops.global_view(), b)
        r = srv.get('/decompile', {'name': 'main'})
        self.assertEqual(r.status, 200)
        self.assertIn('tagcheck("B")', r.json['decompiled'])
        self.assertEqual(r.json['_binary']['resolved_by'], 'global')
        self.assertTrue(r.json['binary_defaulted'])
        self.assertEqual(len(r.json['open_binaries']), 2)
        r = srv.get('/selectBinary', {'view': 'foo.dll'})
        self.assertEqual(r.json['status'], 'ok')
        self.assertIs(srv.ops.global_view(), a)
        r = srv.get('/decompile', {'name': 'main'})
        self.assertIn('tagcheck("A")', r.json['decompiled'])
        r = srv.get('/decompile', {'name': 'main', 'binary': 'bar.dll'})
        self.assertIn('tagcheck("B")', r.json['decompiled'])
        self.assertNotIn('binary_defaulted', r.json)
        self.assertIs(srv.ops.global_view(), a)          # an explicit binary never changes the selection

    def test_patch_bytes_save_to_file_is_refused_and_save_is_never_called(self):
        a = self.view('a')
        srv = self.started(self.m)
        srv.ops.current_view = a
        for method, params in (('GET', {'address': '0x140002060', 'data': '90', 'save_to_file': 'true'}),
                               ('GET', {'address': '0x140002061', 'data': '91'}),
                               ('POST', {'address': '0x140002062', 'data': '92', 'save_to_file': True})):
            with self.subTest(method=method, params=params):
                r = srv.get('/patch', params) if method == 'GET' else srv.post('/patch', json_body=params)
                self.assertEqual(r.status, 200, r.raw[:300])
                self.assertEqual(r.json['status'], 'ok')
                self.assertIs(r.json['saved_to_file'], False)
                self.assertIs(r.json['save_refused'], True)
                self.assertIn('BN_MCP_ALLOW_SAVE', r.json['save_error'])
        self.assertEqual(a.save_calls, [])
        self.assertEqual(a.read(0x140002060, 3), b'\x90\x91\x92')   # the in-memory patch still applies
        self.assertEqual(len(srv.ops.raw_patches('1')), 3)
        st = srv.get('/status', {'binary': a.file.filename}).json
        self.assertTrue(st['_binary']['modified'])
        self.assertIn('save_policy', st['server']['capabilities'])

    def test_patch_bytes_save_only_with_the_explicit_opt_in(self):
        a = self.view('a')
        srv = self.started(self.m, allow_save=True)
        srv.ops.current_view = a
        r = srv.get('/patch', {'address': '0x140002060', 'data': '90', 'save_to_file': '1'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertIs(r.json['saved_to_file'], True)
        self.assertEqual(a.save_calls, [a.file.filename])   # the fake records the call; it never writes a file

    def test_the_data_label_regex_path_works(self):
        a = self.view('a')
        srv = self.started(self.m)
        srv.ops.current_view = a
        for name in ('dword_140002010', 'DWORD_140002010', 'data_0x140002010', 'Unk_140002010'):
            with self.subTest(name=name):
                r = srv.get('/hexdumpByName', {'name': name, 'length': '4'})
                self.assertEqual(r.status, 200, r.raw[:200])
                self.assertTrue(r.raw.decode().startswith('140002010  %s:' % name), r.raw[:80])
                r = srv.get('/getDataDecl', {'name': name})
                self.assertEqual(r.status, 200, r.raw[:200])
                self.assertEqual(r.json['address'], '0x140002010')
        r = srv.get('/hexdumpByName', {'name': 'xdword_140002010'})
        self.assertEqual(r.status, 404)

    def test_status_keeps_legacy_keys_and_reports_the_contract(self):
        a = self.view('a')
        srv = self.started(self.m)
        srv.ops.current_view = a
        st = srv.get('/status').json
        self.assertIs(st['loaded'], True)
        self.assertEqual(st['filename'], a.file.filename)
        sv = st['server']
        self.assertEqual(sv['contract'], H.CONTRACT)
        self.assertEqual(sv['version'], '1.0.0')
        self.assertEqual(sv['import_errors'], {})
        for cap in ('per_call_binary', 'ambiguity_errors', 'output_caps', 'analysis_state', 'save_policy',
                    'post_type_routes', 'expert_v1', 'local_auth_v1'):
            self.assertIn(cap, sv['capabilities'])
        self.assertTrue(set(sv['capabilities']) <= {'per_call_binary', 'ambiguity_errors', 'output_caps',
                                                     'analysis_state', 'save_policy', 'post_type_routes', 'expert_v1',
                                                     'local_auth_v1', 'threaded_per_view'})
        self.assertEqual(set(sv), {'version', 'contract', 'lock_mode', 'threaded', 'max_inflight', 'bn_core_version',
                                   'capabilities', 'import_errors', 'pid', 'auth'})
        self.assertEqual(sv['pid'], os.getpid())
        self.assertEqual(sv['bn_core_version'], self.fb_core())
        self.assertNotIn('analysis_state', st)            # unscoped
        st = srv.get('/status', {'binary': a.file.filename}).json
        self.assertEqual(st['analysis_state'], 'IdleState')
        self.assertIsInstance(st['analysis_state'], str)
        self.assertEqual(st['analysis_state_code'], 2)
        self.assertEqual(st['_binary']['analysis_state'], 'IdleState')
        a.analysis_state = self.fb_enums().AnalysisState.AnalyzeState
        st = srv.get('/status', {'binary': a.file.filename}).json
        self.assertEqual(st['analysis_state'], 'AnalyzeState')
        self.assertEqual(st['_binary']['analysis_state'], 'AnalyzeState')
        empty = self.started(self.m)
        st = empty.get('/status').json
        self.assertEqual((st['loaded'], st['filename']), (False, None))
        self.assertEqual(st['server']['contract'], H.CONTRACT)

    def fb_core(self):
        return H.ensure_fake().core_version()

    def fb_enums(self):
        return H.ensure_fake().enums

    def test_contract_is_empty_when_expert_ops_cannot_be_imported(self):
        a = self.view('a')
        srv = self.started(self.m)
        srv.ops.current_view = a
        name = self.m.alias + '.core.expert_ops'
        saved = sys.modules.get(name)
        sys.modules[name] = None                          # importlib.import_module now raises ModuleNotFoundError
        self.m.http_server.reset_module_status()
        try:
            sv = srv.get('/status').json['server']
            self.assertEqual(sv['contract'], '')
            self.assertIn('expert_ops', sv['import_errors'])
            self.assertTrue(sv['import_errors']['expert_ops'])
            self.assertLessEqual(len(sv['import_errors']['expert_ops']), 200)
            self.assertNotIn('expert_v1', sv['capabilities'])
            self.assertIn('per_call_binary', sv['capabilities'])
        finally:
            sys.modules[name] = saved
            self.m.http_server.reset_module_status()
        sv = srv.get('/status').json['server']
        self.assertEqual(sv['contract'], H.CONTRACT)
        self.assertEqual(sv['import_errors'], {})


class GrammarAndImportTests(unittest.TestCase):
    """Binary Ninja embeds its own Python and the bridge runs in a venv: every plugin .py file must parse
    with the Python 3.10 grammar; and the suite must never execute plugin/__init__.py (Binary Ninja UI glue)."""

    def test_every_plugin_python_file_parses_with_the_310_grammar(self):
        import ast
        files = H.plugin_py_files()
        self.assertTrue(any(f.endswith(os.path.join('core', 'expert_ops.py')) for f in files))
        self.assertTrue(any(f.endswith(os.path.join('bridge', 'binja_mcp_bridge.py')) for f in files))
        bad = []
        for p in files:
            with open(p, encoding='utf-8') as f:
                src = f.read()
            try:
                ast.parse(src, p, feature_version=(3, 10))
            except SyntaxError as e:
                bad.append('%s:%s: %s' % (p, e.lineno, e.msg))
        self.assertEqual(bad, [])

    def test_plugin_init_was_never_executed(self):
        m = H.plugin_modules()
        pkg = sys.modules[m.alias]
        self.assertIsNone(pkg.__file__)
        self.assertFalse(hasattr(pkg, 'BinaryNinjaMCP'))
        self.assertNotIn(m.alias + '.plugin', sys.modules)
        root = os.path.normcase(os.path.join(H.plugin_dir(), 'plugin'))
        for name, mod in list(sys.modules.items()):
            f = getattr(mod, '__file__', None) or ''
            if os.path.normcase(f) == os.path.join(root, '__init__.py'):
                self.fail('plugin/__init__.py was imported as %s' % name)
        bn = H.ensure_fake()
        self.assertIn('fake_bn', bn.__file__)

    def test_no_bytecode_is_written_into_the_plugin_tree(self):
        self.assertTrue(sys.dont_write_bytecode)


if __name__ == '__main__':
    unittest.main()
