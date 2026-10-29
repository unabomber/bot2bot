import http.client
import json
import os
import tempfile
import threading
import unittest

from relay.domain import Domain
from relay.server import make_server
from relay.store import Store


class SyncV2ServerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), 'v2.db'))
        self.domain = Domain(self.store, thread_budget=5)
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

    def test_respond_renew_resume_work_end_to_end_over_http(self):
        status, body = self.call('POST', '/rooms/alpha/state/propose', 'a', {'base_version': 0, 'state': 'S1', 'deadline_seconds': 120})
        self.assertEqual(status, 200, body)
        resume = self.call('GET', '/rooms/alpha/resume', 'b')[1]
        self.assertEqual((resume['outstanding'], resume['round']['state']), ('ack', 'S1'))
        reply = {'ack_version': 1, 'base_version': 1, 'state': 'S2', 'key': 'k1'}
        status, body = self.call('POST', '/rooms/alpha/state/respond', 'b', reply)
        self.assertEqual(status, 200, body)
        self.assertFalse(body['replayed'])
        status, body = self.call('POST', '/rooms/alpha/state/respond', 'b', reply)
        self.assertEqual((status, body['replayed']), (200, True))
        self.assertEqual(self.call('POST', '/rooms/alpha/state/respond', 'b', {**reply, 'key': None})[0], 400)
        status, body = self.call('POST', '/rooms/alpha/state/renew', 'a', {'version': 2, 'seconds': 3600})
        self.assertEqual(status, 200, body)
        self.assertGreater(body['round']['remaining'], 3000)
        self.assertEqual(self.call('GET', '/rooms/alpha/resume', 'a')[1]['outstanding'], 'ack')

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
        self.domain.system_notice('alpha', ['a', 'b'], 'INFO repeated stall notice', 'info')
        self.call('POST', '/rooms/alpha/say', 'b', {'to': ['a'], 'text': 'real message'})
        self.domain.system_notice('alpha', ['a', 'b'], 'CRIT proposal expired', 'critical')
        status, body = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1&level=warn', 'a')
        self.assertEqual(status, 200, body)
        self.assertEqual([m['text'] for m in body['messages']], ['real message', 'CRIT proposal expired'])
        status, body = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1', 'a')
        self.assertEqual(len(body['messages']), 3)                       # unfiltered wait still sees everything

    def test_filtered_wait_that_skips_everything_still_returns_cursor_and_sync(self):
        self.domain.system_notice('alpha', ['a', 'b'], 'INFO only', 'info')
        status, body = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1&level=critical', 'a')
        self.assertEqual(status, 200, body)
        self.assertEqual(body['messages'], [])
        self.assertTrue(body['timeout'])
        self.assertGreaterEqual(body['cursor'], 1)                       # skipped rows are not re-read forever
        self.assertIn('sync', body)

    def test_unknown_level_is_rejected(self):
        self.assertEqual(self.call('GET', '/rooms/alpha/wait?after=0&timeout=1&level=loud', 'a')[0], 400)

    def test_http_errors_state_the_limit_and_the_size_received(self):
        ok = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 'big', 'text': 'x' * 16384})
        self.assertEqual(ok[0], 200, ok)
        status, body = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 'big', 'text': 'x' * 16385})
        self.assertEqual((status, body['error']), (413, 'text exceeds 16384 UTF-8 bytes (received 16385)'))
        status, body = self.call('POST', '/rooms/alpha/state/propose', 'a', {'base_version': 0, 'state': 's' * 16385})
        self.assertEqual((status, body['error']), (400, 'state exceeds 16384 UTF-8 bytes (received 16385)'))
        status, body = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'text': 'x' * 70000})
        self.assertEqual(status, 413)
        self.assertIn('exceeds 65536 bytes (received', body['error'])

    def test_heartbeat_is_presence_only_and_never_touches_message_reads(self):
        self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'text': 'hello'})
        for _ in range(5):
            status, body = self.call('POST', '/rooms/alpha/heartbeat', 'b')
            self.assertEqual(status, 200, body)
            self.assertIn('sync', body)
            self.assertNotIn('messages', body)
        first = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1', 'b')[1]
        second = self.call('GET', '/rooms/alpha/wait?after=0&timeout=1', 'b')[1]       # a second consumer, same name
        self.assertEqual([m['text'] for m in first['messages']], ['hello'])
        self.assertEqual([m['text'] for m in second['messages']], ['hello'])
        self.assertEqual(self.server.hub.waits.get(('alpha', 'b'), 0), 0)               # nothing left holding a wait slot
        members = {m['name']: m for m in self.call('GET', '/rooms/alpha/members', 'eye')[1]['members']}
        self.assertTrue(members['b']['active'])
        self.assertFalse(members['b'].get('waiting'))

    # ---- settings ----
    def test_proposal_seconds_setting_is_accepted_over_http(self):
        status, body = self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', {'proposal_seconds': 3600})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', {'bogus': 1})[0], 400)


if __name__ == '__main__':
    unittest.main()
