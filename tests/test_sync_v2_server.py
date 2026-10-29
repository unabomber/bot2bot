import http.client
import inspect
import json
import os
import tempfile
import threading
import unittest

from relay.domain import Domain
from relay.server import make_server
from relay.store import Store


class ShimDomain(Domain):
    """Fills in the backend calls the server layer depends on only while the backend branch lacks them,
    so these tests exercise the HTTP layer either way. Once the real methods exist nothing is overridden."""
    calls = None

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.calls = []

    if not hasattr(Domain, 'sync_respond'):
        def sync_respond(self, p, room, ack_version, base_version, state, phase=None, deadline_seconds=None, key=None):
            self.calls.append(('respond', ack_version, base_version, state, key))
            return {'acked': {'version': ack_version}, 'round': {'version': 99}, 'replayed': False}

        def sync_renew(self, p, room, version, seconds):
            self.calls.append(('renew', version, seconds))
            return {'version': version, 'remaining': seconds}

        def sync_resume(self, p, room):
            self.calls.append(('resume',))
            return {'committed': {'version': 0}, 'round': None, 'latest_id': 0, 'outstanding': 'none'}

    if not hasattr(Domain, 'room_thread_budget'):
        def room_thread_budget(self, p, room, thread):
            return {'used': 4, 'limit': 5, 'remaining': 1}

    if 'proposal_seconds' not in inspect.signature(Domain.set_room_sync).parameters:
        def set_room_sync(self, admin, room, proposal_seconds=None, **kw):
            self.calls.append(('settings', proposal_seconds))
            return super().set_room_sync(admin, room, **kw)

    def room_fetch(self, p, room, after=0, limit=100):
        rows = super().room_fetch(p, room, after, limit)
        for row in rows:
            if row.get('source') == 'system' and 'level' not in row:
                row['level'] = 'critical' if row['text'].startswith('CRIT') else 'info'
        return rows


class SyncV2ServerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), 'v2.db'))
        self.domain = ShimDomain(self.store, thread_budget=5)
        self.tok = {'root': self.domain.mint_agent('root', 'admin')}
        self.server = make_server(self.domain, '127.0.0.1', 0, sync_interval=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.addCleanup(self.store.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        status, body = self.call('POST', '/admin/rooms', 'root', {'name': 'alpha', 'members': ['a', 'b']})
        self.assertEqual(status, 200, body)
        for m in body['members']:
            self.tok[m['name']] = m['token']
        self.tok['eye'] = self.call('POST', '/admin/rooms/alpha/members', 'root', {'name': 'eye', 'role': 'monitor'})[1]['token']

    def call(self, method, path, who=None, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        headers = {'Authorization': f'Bearer {self.tok[who]}'} if who else {}
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode()
        conn.close()
        try:
            return resp.status, json.loads(text)
        except ValueError:
            return resp.status, text

    # ---- new routes ----
    def test_respond_renew_resume_are_agent_only_routes(self):
        for method, path, body in (('POST', '/rooms/alpha/state/respond', {}), ('POST', '/rooms/alpha/state/renew', {}),
                                   ('GET', '/rooms/alpha/resume', None)):
            for who in ('eye', 'root'):
                self.assertEqual(self.call(method, path, who, body)[0], 403, (path, who))
            self.assertEqual(self.call(method, path)[0], 401, path)
        self.assertEqual(self.call('POST', '/rooms/beta/state/respond', 'a', {})[0], 403)   # not a member of beta

    def test_routes_pass_arguments_through_to_the_domain(self):
        if not isinstance(self.domain.calls, list) or hasattr(Domain, 'sync_respond'):
            self.skipTest('real backend present: covered by integration tests')
        self.call('POST', '/rooms/alpha/state/respond', 'a',
                  {'ack_version': 3, 'base_version': 3, 'state': 's', 'key': 'k1'})
        self.call('POST', '/rooms/alpha/state/renew', 'a', {'version': 4, 'seconds': 600})
        self.assertEqual(self.call('GET', '/rooms/alpha/resume', 'a')[1]['outstanding'], 'none')
        self.assertEqual([c[0] for c in self.domain.calls], ['respond', 'renew', 'resume'])
        self.assertEqual(self.domain.calls[0], ('respond', 3, 3, 's', 'k1'))

    # ---- thread budget ----
    def test_say_reports_thread_budget_and_warns_near_the_cap(self):
        status, body = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 'main', 'text': 'hi'})
        self.assertEqual(status, 200, body)
        self.assertEqual(set(body['thread']), {'used', 'limit', 'remaining', 'warning'})
        self.assertEqual(body['thread']['warning'], body['thread']['remaining'] * 5 <= body['thread']['limit'])

    def test_full_thread_gives_a_structured_409_with_a_hint(self):
        for i in range(5):
            self.assertEqual(self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 'full', 'text': str(i)})[0], 200)
        status, body = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 'full', 'text': 'x'})
        self.assertEqual(status, 409)
        self.assertEqual(body['code'], 409)
        self.assertIn('thread', body)
        self.assertIn('new thread', body['hint'])
        self.assertEqual(self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 'fresh', 'text': 'ok'})[0], 200)

    # ---- wait filtering ----
    def test_level_filter_hides_info_notices_but_advances_the_cursor_and_keeps_critical(self):
        self.domain.system_notice('alpha', ['a', 'b'], 'INFO repeated stall notice')
        self.call('POST', '/rooms/alpha/say', 'b', {'to': ['a'], 'text': 'real message'})
        self.domain.system_notice('alpha', ['a', 'b'], 'CRIT proposal expired')
        status, body = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1&level=warn', 'a')
        self.assertEqual(status, 200, body)
        self.assertEqual([m['text'] for m in body['messages']], ['real message', 'CRIT proposal expired'])
        status, body = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1', 'a')
        self.assertEqual(len(body['messages']), 3)                       # unfiltered wait still sees everything

    def test_filtered_wait_that_skips_everything_still_returns_cursor_and_sync(self):
        self.domain.system_notice('alpha', ['a', 'b'], 'INFO only')
        status, body = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1&level=critical', 'a')
        self.assertEqual(status, 200, body)
        self.assertEqual(body['messages'], [])
        self.assertTrue(body['timeout'])
        self.assertGreaterEqual(body['cursor'], 1)                       # skipped rows are not re-read forever
        self.assertIn('sync', body)

    def test_unknown_level_is_rejected(self):
        self.assertEqual(self.call('GET', '/rooms/alpha/wait?after=0&timeout=1&level=loud', 'a')[0], 400)

    # ---- settings ----
    def test_proposal_seconds_setting_is_accepted_over_http(self):
        status, body = self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', {'proposal_seconds': 3600})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', {'bogus': 1})[0], 400)


if __name__ == '__main__':
    unittest.main()
