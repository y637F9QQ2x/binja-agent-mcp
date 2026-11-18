# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Tool sets, tool definitions and the output cap of the bridge (bridge/binja_mcp_bridge.py).

* select_tools(): BN_MCP_TOOLSET / BN_MCP_TOOLS, every error case;
* the tool sets themselves: members exist, core has no overlapping pair, upstream is exactly the upstream names;
* what the MCP client receives per tool set (tools/list as the server serializes it): no outputSchema, no generated
  schema titles, no "See also" line naming an unregistered tool, every description within Claude Code's
  documented 4,096-character limit for upfront-loaded tools, and the numbers README.md states;
* _cap_result and list_all_strings: no answer above the output cap, a cut always says how to page.

Needs mcp, requests and anyio (skipped otherwise, like test_bridge).
"""

import asyncio
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import unittest

import run_tests as H
import test_bridge as TB

# Pairs of tools that do the same job (see README.md "Overlapping tools"). core keeps at most one of each pair.
OVERLAPS = (
    ('decompile_function', 'bn_decompile'), ('get_il', 'bn_decompile'), ('fetch_disassembly', 'bn_decompile'),
    ('get_xrefs_to', 'bn_xrefs'), ('function_at', 'bn_resolve_entity'), ('hexdump_address', 'bn_bytes_at'),
    ('retype_variable', 'set_local_variable_type'), ('define_types', 'declare_c_type'),
    ('get_user_defined_type', 'get_type_info'), ('get_binary_status', 'bn_binary_info'),
    ('rename_single_variable', 'rename_multi_variables'), ('list_all_strings', 'list_strings'),
)
UPFRONT_DESCRIPTION_LIMIT = 4096      # https://code.claude.com/docs/en/mcp, "Tool search for MCP server authors"


def _schema_titles(schema, path='$'):
    """JSON-schema "title" annotations left in `schema` (a key inside "properties" is a parameter name, not one)."""
    out = []
    if isinstance(schema, dict):
        for k, v in schema.items():
            if k == 'title' and isinstance(v, str):
                out.append(path)
            elif k == 'properties' and isinstance(v, dict):
                for pk, pv in v.items():
                    out.extend(_schema_titles(pv, '%s.properties.%s' % (path, pk)))
            else:
                out.extend(_schema_titles(v, '%s.%s' % (path, k)))
    elif isinstance(schema, list):
        for i, x in enumerate(schema):
            out.extend(_schema_titles(x, '%s[%d]' % (path, i)))
    return out


def _skip_unless_importable():
    if not TB._importable():
        raise unittest.SkipTest('mcp/requests/anyio are not importable here')


_LOADED = {}


def bridge_for(toolset=None, tools=None, extra=None):
    """A fresh bridge import whose registration used BN_MCP_TOOLSET=toolset / BN_MCP_TOOLS=tools."""
    key = (toolset, tools, tuple(sorted((extra or {}).items())))
    if key not in _LOADED:
        env = {'BN_MCP_TOOLSET': toolset, 'BN_MCP_TOOLS': tools}
        env.update(extra or {})
        _LOADED[key] = TB.import_bridge('bnmcp_bridge_ts_%d' % len(_LOADED), env)
    return _LOADED[key]


class SelectToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _skip_unless_importable()
        cls.b = TB.load_bridge()
        cls.all = list(cls.b.ALL_TOOLS)

    def sel(self, **env):
        return self.b.select_tools(env, self.all)

    def test_default_is_core(self):
        label, names = self.sel()
        self.assertEqual(label, 'core')
        self.assertEqual(set(names), set(self.b.CORE_TOOLS))
        self.assertEqual(self.b.DEFAULT_TOOLSET, 'core')

    def test_every_named_set_and_case(self):
        for key, members in (('core', self.b.CORE_TOOLS), ('analysis', self.b.ANALYSIS_TOOLS),
                             ('upstream', self.b.UPSTREAM_TOOLS), ('full', self.all)):
            with self.subTest(toolset=key):
                label, names = self.sel(BN_MCP_TOOLSET=' %s ' % key.upper())
                self.assertEqual(label, key)
                self.assertEqual(set(names), set(members))
                self.assertEqual(names, [n for n in self.all if n in set(members)], 'definition order is kept')

    def test_explicit_list_with_sets_names_and_removals(self):
        label, names = self.sel(BN_MCP_TOOLS='core, bn_cfg ,bn_sinks')
        self.assertEqual(label, 'custom')
        self.assertEqual(set(names), set(self.b.CORE_TOOLS) | {'bn_cfg', 'bn_sinks'})
        label, names = self.sel(BN_MCP_TOOLS='full,-patch_bytes,-format_value')
        self.assertEqual(set(names), set(self.all) - {'patch_bytes', 'format_value'})
        label, names = self.sel(BN_MCP_TOOLS='bn_decompile')
        self.assertEqual(names, ['bn_decompile'])
        label, names = self.sel(BN_MCP_TOOLS='bn_decompile,-bn_decompile,bn_cfg')
        self.assertEqual(names, ['bn_cfg'], 'items apply left to right')

    def test_invalid_configurations_raise(self):
        for env, needle in (({'BN_MCP_TOOLSET': 'core', 'BN_MCP_TOOLS': 'bn_cfg'}, 'not both'),
                            ({'BN_MCP_TOOLSET': 'everything'}, 'use one of'),
                            ({'BN_MCP_TOOLS': 'core,no_such_tool'}, 'no_such_tool'),
                            ({'BN_MCP_TOOLS': '-bn_cfg'}, 'selects no tool'),
                            ({'BN_MCP_TOOLS': ' , '}, 'selects no tool'),
                            ({'BN_MCP_TOOLS': '-core'}, 'not a tool name'),
                            ({'BN_MCP_TOOLS': 'Bn_Cfg'}, 'not a tool name')):
            with self.subTest(env=env):
                with self.assertRaises(ValueError) as cm:
                    self.sel(**env)
                self.assertIn(needle, str(cm.exception))

    def test_an_invalid_configuration_registers_nothing_and_the_cli_refuses_to_start(self):
        b = bridge_for(toolset='everything')
        self.assertEqual((b.ACTIVE_TOOLSET, b.ACTIVE_TOOLS), ('invalid', []))
        self.assertIn('everything', b.TOOLSET_ERROR)
        self.assertEqual(asyncio.run(b.mcp.list_tools()), [])
        env = dict(os.environ, BN_MCP_TOOLSET='everything')
        p = subprocess.run([sys.executable, '-I', '-B', TB.bridge_path()], capture_output=True, text=True,
                           timeout=120, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn('not starting', p.stderr)


class ToolSetContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _skip_unless_importable()
        cls.b = TB.load_bridge()

    def test_members_exist_once_and_sets_nest(self):
        all_names = set(self.b.ALL_TOOLS)
        for key in ('CORE_TOOLS', 'ANALYSIS_TOOLS', 'UPSTREAM_TOOLS'):
            members = getattr(self.b, key)
            with self.subTest(toolset=key):
                self.assertEqual(sorted(set(members) - all_names), [])
                self.assertEqual(len(members), len(set(members)), 'a tool is listed twice')
        self.assertTrue(set(self.b.CORE_TOOLS) < set(self.b.ANALYSIS_TOOLS))
        self.assertEqual(len(self.b.UPSTREAM_TOOLS), 53)
        self.assertEqual(sorted(set(all_names) - set(self.b.UPSTREAM_TOOLS)),
                         sorted(n for n in all_names if n.startswith('bn_')), 'full = upstream + bn_*')

    def test_upstream_set_equals_the_upstream_bridge(self):
        self.assertEqual(list(self.b.UPSTREAM_TOOLS), TB.baseline_legacy_tools())

    def test_core_keeps_at_most_one_tool_of_each_overlapping_pair(self):
        core = set(self.b.CORE_TOOLS)
        for a, b in OVERLAPS:
            with self.subTest(pair=(a, b)):
                self.assertIn(a, self.b.ALL_TOOLS)
                self.assertIn(b, self.b.ALL_TOOLS)
                self.assertFalse(a in core and b in core, 'core has both %s and %s' % (a, b))

    def test_every_overlapping_tool_names_its_twin_in_a_see_also_line(self):
        for a, b in OVERLAPS:
            for x, y in ((a, b), (b, a)):
                doc = self.b.ALL_TOOLS[x].__doc__ or ''
                see = [ln for ln in doc.split('\n') if ln.strip().startswith('See also:')]
                with self.subTest(tool=x, twin=y):
                    self.assertTrue(any(y in re.findall(r'\b[a-z][a-z0-9_]*\b', ln) for ln in see),
                                    '%s does not name %s in a See also line' % (x, y))


class DefinitionTests(unittest.TestCase):
    """What the MCP client receives in tools/list, per tool set."""

    @classmethod
    def setUpClass(cls):
        _skip_unless_importable()

    def defs(self, toolset):
        b = bridge_for(toolset=toolset)
        return b, b.tool_definitions()

    def test_registered_names_per_set(self):
        b0 = TB.load_bridge()
        for key, members in (('core', b0.CORE_TOOLS), ('analysis', b0.ANALYSIS_TOOLS),
                             ('upstream', b0.UPSTREAM_TOOLS), ('full', list(b0.ALL_TOOLS))):
            with self.subTest(toolset=key):
                b, defs = self.defs(key)
                self.assertEqual([d['name'] for d in defs], [n for n in b.ALL_TOOLS if n in set(members)])
                self.assertEqual(b.ACTIVE_TOOLSET, key)

    def test_definitions_are_lean_and_self_consistent(self):
        for key in ('core', 'analysis', 'upstream', 'full'):
            b, defs = self.defs(key)
            names = {d['name'] for d in defs}
            for d in defs:
                with self.subTest(toolset=key, tool=d['name']):
                    self.assertEqual(set(d), {'name', 'description', 'inputSchema'})
                    self.assertEqual(_schema_titles(d['inputSchema']), [], 'a generated schema title is left')
                    self.assertLessEqual(len(d['description']), UPFRONT_DESCRIPTION_LIMIT)
                    self.assertNotIn('\u2014', d['description'])
                    self.assertNotIn('\u2013', d['description'])
                    for line in d['description'].split('\n'):
                        if line.startswith('See also:'):
                            refs = [t for t in re.findall(r'\b[a-z][a-z0-9_]*\b', line) if t in b.ALL_TOOLS]
                            self.assertTrue(refs, line)
                            self.assertEqual(sorted(set(refs) - names), [], line)
                    props = d['inputSchema'].get('properties', {})
                    sig = TB.inspect.signature(b.ALL_TOOLS[d['name']])
                    self.assertEqual(list(props), list(sig.parameters))

    def test_strip_titles_keeps_a_parameter_named_title(self):
        b = TB.load_bridge()
        schema = {'title': 'xArguments', 'type': 'object',
                  'properties': {'title': {'title': 'Title', 'type': 'string'}, 'n': {'title': 'N', 'type': 'integer'}},
                  'required': ['title']}
        self.assertEqual(b._strip_schema_titles(schema),
                         {'type': 'object', 'properties': {'title': {'type': 'string'}, 'n': {'type': 'integer'}},
                          'required': ['title']})

    def test_readme_numbers_match_the_measurement(self):
        readme = os.path.join(os.path.dirname(H.plugin_dir()), 'README.md')
        if not os.path.isfile(readme):
            self.skipTest('no README.md next to the plugin tree')
        text = open(readme, encoding='utf-8').read()
        rows = {m.group(1): (int(m.group(2)), int(m.group(3).replace(',', '')))
                for m in re.finditer(r'^\| `(core|analysis|upstream|full)`[^|]*\| (\d+) \| ([\d,]+) \|', text, re.M)}
        self.assertEqual(sorted(rows), ['analysis', 'core', 'full', 'upstream'], 'README.md has no measurement table')
        for key, (n_tools, n_chars) in rows.items():
            with self.subTest(toolset=key):
                b, defs = self.defs(key)
                total = len(b._dump({'tools': defs}))
                self.assertEqual((len(defs), total), (n_tools, n_chars),
                                 'README.md states %d tools / %d characters for %s; measured %d / %d'
                                 % (n_tools, n_chars, key, len(defs), total))

    def test_list_tools_cli(self):
        env = dict(os.environ, BN_MCP_TOOLSET='core')
        p = subprocess.run([sys.executable, '-I', '-B', TB.bridge_path(), '--list-tools', '--json'],
                           capture_output=True, text=True, timeout=120, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        b, defs = self.defs('core')
        self.assertEqual((out['toolset'], out['tools'], out['tools_list_chars']),
                         ('core', len(defs), len(b._dump({'tools': defs}))))
        self.assertEqual(list(out['per_tool_chars']), [d['name'] for d in defs])


class OutputCapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _skip_unless_importable()
        cls.b = TB.load_bridge()
        cls.cap = cls.b.MCP_OUTPUT_CAP_CHARS

    def test_default_cap_and_the_environment_override(self):
        self.assertEqual(self.cap, 48000)
        old = os.environ.get('BN_MCP_MAX_OUTPUT_CHARS')
        self.addCleanup(lambda: os.environ.__setitem__('BN_MCP_MAX_OUTPUT_CHARS', old) if old is not None
                        else os.environ.pop('BN_MCP_MAX_OUTPUT_CHARS', None))
        for raw, want in (('20000', 20000), (' 500000 ', 500000), ('8000', 8000), ('7999', 48000), ('500001', 48000),
                          ('abc', 48000), ('', 48000)):
            with self.subTest(raw=raw):
                os.environ['BN_MCP_MAX_OUTPUT_CHARS'] = raw
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(self.b._output_cap_from_env(), want)
                self.assertEqual('ignoring' in err.getvalue(), want == 48000 and raw.strip() not in ('', '48000'))

    def test_short_answers_pass_and_lists_become_one_text(self):
        self.assertEqual(self.b._cap_result('abc'), 'abc')
        self.assertEqual(self.b._cap_result(['a', 'b', None, 3]), 'a\nb\n\n3')
        self.assertEqual(self.b._cap_result({'k': 1}), {'k': 1})

    def test_a_long_answer_is_cut_at_a_line_boundary_and_says_how_to_page(self):
        lines = ['%06d %s' % (i, 'x' * 90) for i in range(2000)]
        for fn, advice in ((self.b.decompile_function, 'line_offset'), (self.b.list_methods, 'smaller limit'),
                           (self.b.list_strings, 'smaller count'), (self.b.get_xrefs_to, 'Narrow the request')):
            with self.subTest(tool=fn.__name__):
                out = self.b._cap_result(lines, fn)
                self.assertLessEqual(self.b._clen(out), self.cap)
                body, marker = out.rsplit('\n', 1)
                self.assertTrue(marker.startswith('[TRUNCATED by the bridge: the answer has'), marker)
                self.assertIn(advice, marker)
                self.assertTrue(body.split('\n')[-1] in lines, 'the cut is not at a line boundary')
                self.assertEqual(body.split('\n'), lines[:len(body.split('\n'))])

    def test_the_cap_counts_utf16_code_units(self):
        text = ('\U0001F600' * 30 + '\n') * 2000        # each emoji is 2 UTF-16 code units
        out = self.b._cap_result(text, self.b.decompile_function)
        self.assertLessEqual(self.b._clen(out), self.cap)
        self.assertIn('[TRUNCATED by the bridge', out)
        one = 'y' * (self.cap * 2)                       # a single line longer than the cap: cut mid-line
        out = self.b._cap_result(one, self.b.decompile_function)
        self.assertLessEqual(self.b._clen(out), self.cap)
        self.assertTrue(out.startswith('yyyy'))

    def test_registered_upstream_tools_are_capped_through_mcp(self):
        stub = H.StubHTTP()
        self.addCleanup(stub.close)
        saved = self.b.binja_server_url
        self.addCleanup(setattr, self.b, 'binja_server_url', saved)
        self.b.binja_server_url = stub.url
        big = '\n'.join('line %d %s' % (i, 'z' * 100) for i in range(3000))
        stub.routes['/decompile'] = (200, {'decompiled': big, '_binary': {'filename': 'C:/x.dll'}})
        stub.routes['/methods'] = (200, {'unused': True})
        res = asyncio.run(self.b.mcp.call_tool('decompile_function', {'name': 'main'}))
        blocks = res[0] if isinstance(res, tuple) else res
        self.assertEqual(len(blocks), 1)
        text = blocks[0].text
        self.assertLessEqual(self.b._clen(text), self.cap)
        self.assertIn('[TRUNCATED by the bridge', text)
        self.assertIn('line_offset', text.rsplit('\n', 1)[1])

    def test_list_all_strings_stops_at_the_cap_with_the_exact_continuation(self):
        stub = H.StubHTTP()
        self.addCleanup(stub.close)
        saved = self.b.binja_server_url
        self.addCleanup(setattr, self.b, 'binja_server_url', saved)
        self.b.binja_server_url = stub.url

        def pages(rec):
            off = int(rec['query'].get('offset') or 0)
            lim = int(rec['query'].get('limit') or 0)
            if off >= 100000:
                return 200, {'strings': []}
            return 200, {'strings': [{'address': hex(0x1000 + i), 'length': 64, 'type': 'ascii',
                                      'value': 's%07d' % i + 'v' * 56} for i in range(off, off + lim)]}
        stub.routes['/strings'] = pages
        out = self.b.list_all_strings(batch_size=500)
        text = self.b._cap_result(out, self.b.list_all_strings)
        self.assertLessEqual(self.b._clen(text), self.cap)
        last = out[-1]
        m = re.match(r'^\[INCOMPLETE: stopped at offset (\d+) after (\d+) string\(s\).*list_strings\(offset=(\d+), '
                     r'count=500\)\]$', last)
        self.assertTrue(m, last)
        self.assertEqual(int(m.group(1)), len(out) - 1)
        self.assertEqual(int(m.group(1)), int(m.group(3)))
        self.assertEqual(out[-2].split('\t')[3], 's%07d' % (len(out) - 2) + 'v' * 56, 'no string was skipped')
        offsets = sorted({int(r['query']['offset']) for r in stub.log if r['path'] == '/strings'})
        self.assertEqual(offsets, list(range(0, offsets[-1] + 1, 500)), 'pages are read in order, never skipped')
        self.assertLess(offsets[-1], 100000, 'the bridge kept fetching past the cap')


if __name__ == '__main__':
    unittest.main()
