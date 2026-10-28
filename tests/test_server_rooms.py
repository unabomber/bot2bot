import http.client
import json
import os
import tempfile
import threading
import time
import unittest

from relay.domain import Domain
from relay.server import make_server
from relay.store import Store


class RoomServerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), 'r.db'))
        self.domain = Domain(self.store)
        self.tok = {'root': self.domain.mint_agent('root', 'admin'), 'old': self.domain.mint_agent('old', 'agent'),
                    'old2': self.domain.mint_agent('old2', 'agent')}
        self.server = make_server(self.domain, '127.0.0.1', 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.addCleanup(self.store.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        status, body = self.call('POST', '/admin/rooms', 'root', {'name': 'alpha', 'members': ['a', 'b', 'c']})
        self.assertEqual(status, 200, body)
        for m in body['members']:
            self.tok[m['name']] = m['token']
        self.tok['beta_a'] = self.call('POST', '/admin/rooms', 'root', {'name': 'beta', 'members': ['x']})[1]['members'][0]['token']
        status, body = self.call('POST', '/admin/rooms/alpha/members', 'root', {'name': 'eye', 'role': 'monitor'})
        self.assertEqual(status, 200, body)
        self.tok['eye'] = body['token']

    def call(self, method, path, who=None, body=None, raw=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        headers = {'Authorization': f'Bearer {self.tok[who]}'} if who else {}
        data = raw if raw is not None else (json.dumps(body) if body is not None else None)
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode()
        conn.close()
        try:
            return resp.status, json.loads(text)
        except ValueError:
            return resp.status, text

    def say(self, who, to, text='hello', room='alpha', thread='t'):
        return self.call('POST', f'/rooms/{room}/say', who, {'to': to, 'thread': thread, 'text': text})

    def test_room_chat_and_broadcast(self):
        self.assertEqual(self.say('a', ['b'], 'only-b')[0], 200)
        self.assertEqual(self.say('a', '*', 'everyone')[0], 200)
        b = self.call('GET', '/rooms/alpha/wait?timeout=1', 'b')[1]['messages']
        c = self.call('GET', '/rooms/alpha/wait?timeout=1', 'c')[1]['messages']
        self.assertEqual([m['text'] for m in b], ['only-b', 'everyone'])
        self.assertEqual([m['text'] for m in c], ['everyone'])
        self.assertTrue(all(m['untrusted'] for m in b + c))
        self.assertEqual(self.say('a', ['nobody'])[0], 400)
        self.assertEqual(self.say('a', 'b')[0], 400)

    def test_tokens_are_room_bound(self):
        self.assertEqual(self.say('beta_a', '*', room='alpha')[0], 403)
        self.assertEqual(self.call('GET', '/rooms/alpha/messages', 'beta_a')[0], 403)
        self.assertEqual(self.call('GET', '/rooms/nonexistent/messages', 'root')[0], 404)
        self.assertEqual(self.call('GET', '/rooms/nonexistent/messages', 'a')[0], 403)

    def test_monitor_sees_metadata_only(self):
        self.say('a', ['b'], 'SECRETPAYLOAD', thread='secret-label')
        status, body = self.call('GET', '/rooms/alpha/monitor', 'eye')
        self.assertEqual(status, 200)
        text = json.dumps(body)
        self.assertNotIn('SECRETPAYLOAD', text)
        self.assertNotIn('secret-label', text)
        event = body['events'][0]
        self.assertEqual((event['from'], event['to_count'], event['bytes'], event['source']), ('a', 1, 13, 'agent'))
        stats = self.call('GET', '/rooms/alpha/stats', 'eye')
        self.assertEqual(stats[0], 200)
        self.assertNotIn('SECRETPAYLOAD', json.dumps(stats[1]))
        self.assertEqual(self.call('GET', '/rooms/alpha/members', 'eye')[0], 200)

    def test_monitor_denied_everything_with_content(self):
        for method, path in [('GET', '/rooms/alpha/messages'), ('GET', '/rooms/alpha/wait?timeout=0'),
                             ('GET', '/rooms/alpha/tasks'), ('GET', '/observe'), ('GET', '/messages'),
                             ('GET', '/tasks'), ('GET', '/admin/rooms')]:
            self.assertEqual(self.call(method, path, 'eye')[0], 403, path)
        self.assertEqual(self.call('POST', '/rooms/alpha/say', 'eye', {'to': '*', 'text': 'x'})[0], 403)
        self.assertEqual(self.call('POST', '/rooms/alpha/task', 'eye', {'title': 't', 'files': ['f']})[0], 403)

    def test_agents_cannot_use_monitor_or_admin(self):
        for path in ('/rooms/alpha/monitor', '/rooms/alpha/stats', '/rooms/alpha/members'):
            self.assertEqual(self.call('GET', path, 'a')[0], 403, path)
        for path in ('/admin/rooms/alpha/inject', '/admin/rooms/alpha/close', '/admin/rooms/alpha/members'):
            self.assertEqual(self.call('POST', path, 'a', {'to': '*', 'text': 'x', 'name': 'z'})[0], 403, path)
        self.assertEqual(self.call('GET', '/admin/rooms', 'a')[0], 403)
        for alias in ('/admin_rooms', '/admin/rooms/', '/admin//rooms', '/ADMIN/rooms', '/admin/rooms/alpha/Close'):
            self.assertEqual(self.call('POST', alias, 'a', {})[0], 404, alias)

    def test_human_injection(self):
        status, body = self.call('POST', '/admin/rooms/alpha/inject', 'root', {'to': ['b'], 'text': 'for-b-only'})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/inject', 'root', {'to': '*', 'text': 'to-all'})[0], 200)
        b = self.call('GET', '/rooms/alpha/wait?timeout=1', 'b')[1]['messages']
        c = self.call('GET', '/rooms/alpha/wait?timeout=1', 'c')[1]['messages']
        self.assertEqual([(m['text'], m['source'], m['from']) for m in b],
                         [('for-b-only', 'human', 'human'), ('to-all', 'human', 'human')])
        self.assertEqual([m['text'] for m in c], ['to-all'])
        sources = [e['source'] for e in self.call('GET', '/rooms/alpha/monitor', 'eye')[1]['events']]
        self.assertEqual(sources, ['human', 'human'])
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/inject', 'root', {'to': '*', 'text': 'x' * 9000})[0], 413)

    def test_impersonating_human_rejected(self):
        self.assertEqual(self.call('POST', '/rooms/alpha/say', 'a', {'from': 'human', 'to': '*', 'text': 'x'})[0], 400)

    def test_presence(self):
        members = self.call('GET', '/rooms/alpha/members', 'eye')[1]['members']
        self.assertFalse(any(m['active'] for m in members if m['name'] in ('a', 'b', 'c')))  # eye's own call touches it
        self.assertEqual(self.call('POST', '/rooms/alpha/heartbeat', 'a')[0], 200)
        result = {}
        t = threading.Thread(target=lambda: result.update(r=self.call('GET', '/rooms/alpha/wait?timeout=3', 'b')))
        t.start()
        time.sleep(0.6)
        members = {m['name']: m for m in self.call('GET', '/rooms/alpha/members', 'eye')[1]['members']}
        self.assertTrue(members['a']['active'])
        self.assertEqual(members['b']['waiting'], 1)
        self.assertEqual(members['c']['waiting'], 0)
        t.join(10)
        rooms = self.call('GET', '/admin/rooms', 'root')[1]['rooms']
        self.assertEqual({r['name'] for r in rooms}, {'alpha', 'beta', 'default'})

    def test_close_and_reopen(self):
        self.say('a', ['b'])
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/close', 'root')[0], 200)
        self.assertEqual(self.say('a', ['b'])[0], 423)
        status, body = self.call('GET', '/rooms/alpha/wait?after=1&timeout=1', 'b')
        self.assertEqual((status, body['closed']), (200, True))
        self.assertEqual(self.call('GET', '/rooms/alpha/messages', 'b')[1]['closed'], True)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/inject', 'root', {'to': '*', 'text': 'still works'})[0], 200)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/reopen', 'root')[0], 200)
        self.assertEqual(self.say('a', ['b'])[0], 200)

    def test_revoke_interrupts_wait_and_blocks_reads(self):
        result = {}
        t = threading.Thread(target=lambda: result.update(r=self.call('GET', '/rooms/alpha/wait?timeout=30', 'b')))
        t.start()
        time.sleep(0.5)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/members/b/revoke', 'root')[0], 200)
        t.join(8)
        self.assertFalse(t.is_alive())
        self.assertEqual(result['r'][0], 403)
        self.assertEqual(self.call('GET', '/rooms/alpha/messages', 'b')[0], 401)

    def test_rotate_invalidates_old_token_and_inflight_wait(self):
        result = {}
        t = threading.Thread(target=lambda: result.update(r=self.call('GET', '/rooms/alpha/wait?timeout=30', 'b')))
        t.start()
        time.sleep(0.5)
        status, body = self.call('POST', '/admin/rooms/alpha/members/b/rotate', 'root')
        self.assertEqual(status, 200)
        t.join(8)
        self.assertEqual(result['r'][0], 403)
        self.assertEqual(self.call('GET', '/rooms/alpha/messages', 'b')[0], 401)
        self.tok['b'] = body['token']
        self.assertEqual(self.call('GET', '/rooms/alpha/messages', 'b')[0], 200)

    def test_legacy_default_room_and_alias(self):
        self.assertEqual(self.call('POST', '/say', 'old', {'to': 'old2', 'text': 'legacy'})[0], 200)
        got = self.call('GET', '/rooms/default/wait?timeout=1', 'old2')
        self.assertEqual(got[0], 200, got)
        self.assertEqual(got[1]['messages'][0]['text'], 'legacy')
        self.assertEqual(self.call('GET', '/rooms/alpha/messages', 'old')[0], 403)

    def test_wait_envelope_shapes(self):
        self.call('POST', '/say', 'old', {'to': 'old2', 'text': 'one'})
        legacy = self.call('GET', '/wait?timeout=1', 'old2')[1]['messages'][0]
        self.assertEqual(legacy['to'], 'old2')            # v1 envelope: scalar
        room = self.call('GET', '/rooms/default/wait?timeout=1', 'old2')[1]['messages'][0]
        self.assertEqual(room['to'], ['old2'])            # room envelope: list
        self.assertEqual(self.call('GET', '/rooms/default/messages', 'old2')[1]['messages'][0]['to'], ['old2'])

    def test_queued_messages_in_closed_room_report_closed(self):
        self.say('a', ['b'], 'queued')
        self.call('POST', '/admin/rooms/alpha/close', 'root')
        status, body = self.call('GET', '/rooms/alpha/wait?timeout=1', 'b')
        self.assertEqual((status, body['closed'], [m['text'] for m in body['messages']]), (200, True, ['queued']))

    def test_default_room_wait_reauthenticates(self):
        result = {}
        t = threading.Thread(target=lambda: result.update(r=self.call('GET', '/rooms/default/wait?timeout=30', 'old2')))
        t.start()
        time.sleep(0.5)
        self.domain.revoke('old2')
        t.join(8)
        self.assertFalse(t.is_alive())
        self.assertEqual(result['r'][0], 403)

    def test_room_tasks_isolated(self):
        self.assertEqual(self.call('POST', '/rooms/alpha/task', 'a', {'title': 't', 'files': ['f.py']})[0], 200)
        self.assertEqual(self.call('POST', '/rooms/beta/task', 'beta_a', {'title': 't', 'files': ['f.py']})[0], 200)
        self.assertEqual(len(self.call('GET', '/rooms/alpha/tasks', 'b')[1]['tasks']), 1)

    def test_create_room_validation(self):
        for body in ({'name': 'bad name'}, {'name': 'x', 'members': 'a'}, {'name': 'default'}, {'name': 'human'}, {}):
            self.assertEqual(self.call('POST', '/admin/rooms', 'root', body)[0], 400, body)
        self.assertEqual(self.call('POST', '/admin/rooms', 'root', {'name': 'alpha'})[0], 409)


    def test_legacy_routes_reject_room_credentials(self):
        # same identity name exists in default (legacy) and in alpha; the alpha token must not touch legacy state
        self.domain.mint_agent('twin', 'agent')
        self.call('POST', '/admin/rooms/alpha/members', 'root', {'name': 'twin'})
        status, body = self.call('POST', '/admin/rooms/alpha/members/twin/rotate', 'root')
        self.tok['twin_alpha'] = body['token']
        before = (self.call('GET', '/tasks', 'root')[1], self.call('GET', '/status', 'root')[1])
        for method, path, payload in [('GET', '/tasks', None), ('GET', '/status', None), ('GET', '/messages', None),
                                      ('GET', '/wait?timeout=0', None), ('GET', '/observe', None),
                                      ('POST', '/say', {'to': 'old', 'text': 'spoof'}),
                                      ('POST', '/task', {'title': 'spoof', 'files': ['z.py']}),
                                      ('POST', '/done', {'id': 1, 'branch': 'twin/x'}),
                                      ('POST', '/release', {'id': 1}), ('POST', '/admin/pause', {})]:
            self.assertIn(self.call(method, path, 'twin_alpha', payload)[0], (403,), path)
        after = (self.call('GET', '/tasks', 'root')[1], self.call('GET', '/status', 'root')[1])
        self.assertEqual(before, after)
        self.assertFalse(self.domain.is_paused())

    def test_rate_limit_is_per_room_identity(self):
        self.tok['same_default'] = self.domain.mint_agent('same', 'agent')
        self.call('POST', '/admin/rooms/alpha/members', 'root', {'name': 'same'})
        self.tok['same_alpha'] = self.call('POST', '/admin/rooms/alpha/members/same/rotate', 'root')[1]['token']
        for _ in range(40):
            self.call('GET', '/status', 'same_default')
        self.assertEqual(self.call('GET', '/rooms/alpha/messages', 'same_alpha')[0], 200)

    def test_close_wakes_open_wait_promptly(self):
        result = {}
        start = time.monotonic()
        t = threading.Thread(target=lambda: result.update(r=self.call('GET', '/rooms/alpha/wait?timeout=30', 'b')))
        t.start()
        time.sleep(0.5)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/close', 'root')[0], 200)
        t.join(8)
        self.assertFalse(t.is_alive())
        self.assertEqual((result['r'][0], result['r'][1]['closed'], result['r'][1]['messages']), (200, True, []))
        self.assertLess(time.monotonic() - start, 8)

    def test_ids_do_not_leak_other_rooms_traffic(self):
        self.call('POST', '/admin/rooms/beta/members', 'root', {'name': 'y'})
        for i in range(5):
            self.assertEqual(self.call('POST', '/rooms/beta/say', 'beta_a', {'to': ['y'], 'thread': f'th{i}', 'text': 'noise'})[0], 200)
        self.assertEqual(self.say('a', ['b'], 'mine', thread='mine')[0], 200)
        event = self.call('GET', '/rooms/alpha/monitor', 'eye')[1]['events'][0]
        self.assertEqual((event['id'], event['thread_no']), (1, 1))
        msg = self.call('GET', '/rooms/alpha/wait?timeout=1', 'b')[1]
        self.assertEqual((msg['messages'][0]['id'], msg['cursor']), (1, 1))

    def test_monitor_can_heartbeat(self):
        self.assertEqual(self.call('POST', '/rooms/alpha/heartbeat', 'eye')[0], 200)


if __name__ == '__main__':
    unittest.main()
