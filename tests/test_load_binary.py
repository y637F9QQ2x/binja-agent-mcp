# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""The load path. The legacy POST /load is idempotent (a second load of an unchanged file returns the same
server-owned view instead of a second one that would make every path / basename selector 409 AMBIGUOUS), and the new
viewless POST /x/loadBinary {filepath, wait:false} (expert verb load_binary) opens a view through the core API
(bn.load(update_analysis=False), then a non-blocking update_analysis) and answers at once.
"""

import os
import tempfile
import unittest

import run_tests as H


class LoadBinaryTests(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-load-')
        self.addCleanup(self.td.cleanup)
        self.fb = H.fake_bv()
        self.path = self.fb.make_standard_file(self.td.name, 'loadme.dll', 'L')
        self.srv = H.Server(self.m)
        self.srv.start()
        self.addCleanup(self.srv.stop)
        self.bn = H.ensure_fake()
        self.calls = []
        orig = self.bn.load

        def spy(source, update_analysis=True, *a, **k):
            self.calls.append((str(source), update_analysis))
            return orig(source, update_analysis, *a, **k)
        self.bn.load = spy
        self.addCleanup(setattr, self.bn, 'load', orig)

    def owned_stock(self):
        return [b for b in self.srv.ops.list_open_binaries() if b.get('owned')]

    def test_legacy_load_is_idempotent(self):
        r1 = self.srv.post('/load', json_body={'filepath': self.path})
        self.assertEqual(r1.status, 200, r1.raw[:200])
        r2 = self.srv.post('/load', json_body={'filepath': self.path})
        self.assertEqual(r2.status, 200, r2.raw[:200])
        self.assertEqual(len(self.owned_stock()), 1)
        self.assertEqual(len(self.calls), 1, 'the second /load reuses the owned view')
        rr = self.srv.get('/x/binaryInfo', {'binary': 'loadme.dll'})
        self.assertEqual(rr.status, 200, 'no AMBIGUOUS after a repeated /load')
        # the file changes on disk: the loaded bytes no longer equal it, so a new load is a new view
        with open(self.path, 'ab') as f:
            f.write(b'tail')
        r3 = self.srv.post('/load', json_body={'filepath': self.path})
        self.assertEqual(r3.status, 200)
        self.assertEqual(len(self.owned_stock()), 2)

    def test_x_load_binary_is_async_idempotent_and_viewless(self):
        r = self.srv.post('/x/loadBinary', json_body={'filepath': self.path, 'wait': False})
        self.assertEqual(r.status, 200, r.raw[:300])
        res = r.json['result']
        self.assertEqual(r.json['verb'], 'load_binary')
        self.assertTrue(res['view_id'])
        self.assertEqual(len(res['binary_id']), 64)
        self.assertEqual(res['analysis_state'], 'IdleState')
        self.assertIs(res['reused'], False)
        self.assertEqual(self.calls, [(self.path, False)], 'bn.load with update_analysis=False')
        bv = self.srv.ops._obj(res['view_id'])
        self.assertEqual(bv.update_calls, 1, 'one non-blocking update_analysis')
        self.assertIs(self.srv.ops.global_view(), bv, 'an empty global selection is filled')
        r2 = self.srv.post('/x/loadBinary', json_body={'filepath': self.path})
        self.assertEqual((r2.json['result']['view_id'], r2.json['result']['reused']), (res['view_id'], True))
        self.assertEqual(len(self.calls), 1)
        other = self.fb.make_standard_file(self.td.name, 'other.dll', 'O')
        r3 = self.srv.post('/x/loadBinary', json_body={'filepath': other})
        self.assertEqual(r3.status, 200)
        self.assertIs(self.srv.ops.global_view(), bv, 'an existing global selection is kept')

    def test_x_load_binary_refusals(self):
        for body, status in (({'filepath': self.path, 'wait': True}, 400), ({'filepath': 'rel\\x.dll'}, 400),
                             ({}, 400), ({'filepath': os.path.join(self.td.name, 'missing.dll')}, 404)):
            with self.subTest(body=body):
                r = self.srv.post('/x/loadBinary', json_body=body)
                self.assertEqual(r.status, status, r.raw[:200])
                self.assertFalse(r.json['ok'])
        r = self.srv.get('/x/loadBinary', {'filepath': self.path})
        self.assertEqual(r.status, 404, 'POST-only')
        self.assertEqual(self.calls, [], 'every refusal happens before bn.load')
        self.srv.post('/load', json_body={'filepath': self.path})
        n = len(self.calls)
        other = self.fb.make_standard_file(self.td.name, 'other2.dll', 'P')
        r = self.srv.post('/x/batch', params={'binary': self.path},
                          json_body={'items': [{'verb': 'load_binary', 'params': {'filepath': other}}]})
        self.assertEqual(r.status, 200, r.raw[:300])
        item = r.json['result']['items'][0]
        self.assertFalse(item['ok'], 'a batch never runs load_binary')
        self.assertEqual(len(self.calls), n)


if __name__ == '__main__':
    unittest.main()
