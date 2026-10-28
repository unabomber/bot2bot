import http.client
import json
import os
import tempfile
import threading
import time
import unittest

from relay.domain import Domain
from relay.server import MAX_BODY, make_server
from relay.store import Store


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), 's.db'))
        self.domain = Domain(self.store, thread_budget=3)
        self.tokens = {n: self.domain.mint_agent(n, r) for n, r in
                       [('a', 'agent'), ('b', 'agent'), ('root', 'admin'), ('eye', 'observer')]}
        self.server = make_server(self.domain, '127.0.0.1', 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.addCleanup(self.store.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, method, path, who=None, body=None, raw=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = dict(headers or {})
        if who:
            h['Authorization'] = f'Bearer {self.tokens[who]}'
        data = raw if raw is not None else (json.dumps(body) if body is not None else None)
        conn.request(method, path, body=data, headers=h)
        resp = conn.getresponse()
        text = resp.read().decode()
        conn.close()
        try:
            return resp.status, json.loads(text)
        except ValueError:
            return resp.status, text

    def say(self, who, to, text='hi', thread='t'):
        return self.call('POST', '/say', who, {'to': to, 'thread': thread, 'text': text})

    def test_requires_token(self):
        self.assertEqual(self.call('GET', '/status')[0], 401)
        self.assertEqual(self.call('GET', '/status', headers={'Authorization': 'Bearer ' + 'x' * 43})[0], 401)

    def test_token_in_url_rejected(self):
        status, body = self.call('GET', f"/status?key={self.tokens['a']}")
        self.assertEqual(status, 400)

    def test_impersonation_rejected(self):
        status, _ = self.call('POST', '/say', 'a', {'from': 'b', 'to': 'b', 'text': 'x'})
        self.assertEqual(status, 400)
        self.assertEqual(self.say('a', 'b')[0], 200)

    def test_delivery_is_scoped_and_wrapped(self):
        self.say('a', 'b', 'hello')
        status, body = self.call('GET', '/wait?after=0&timeout=1', 'b')
        self.assertEqual(status, 200)
        msg = body['messages'][0]
        self.assertEqual((msg['from'], msg['to'], msg['text'], msg['untrusted']), ('a', 'b', 'hello', True))
        self.assertEqual(self.call('GET', '/messages', 'a')[1]['messages'][0]['id'], msg['id'])
        self.assertEqual(self.call('GET', '/observe', 'eye')[0], 200)
        self.assertEqual(self.call('GET', '/observe', 'a')[0], 403)

    def test_wait_excludes_own_and_times_out(self):
        self.say('a', 'b')
        status, body = self.call('GET', '/wait?after=0&timeout=1', 'a')
        self.assertEqual((status, body['messages'], body['timeout']), (200, [], True))
        self.assertEqual(body['cursor'], 1)

    def test_wait_wakes_on_post(self):
        result = {}
        t = threading.Thread(target=lambda: result.update(r=self.call('GET', '/wait?after=0&timeout=10', 'b')))
        start = time.monotonic()
        t.start()
        time.sleep(0.3)
        self.say('a', 'b', 'wake')
        t.join(5)
        self.assertEqual(result['r'][1]['messages'][0]['text'], 'wake')
        self.assertLess(time.monotonic() - start, 5)

    def test_limits(self):
        self.assertEqual(self.say('a', 'b', 'x' * 8193)[0], 413)
        self.assertEqual(self.call('POST', '/say', 'a', raw='x' * (MAX_BODY + 1))[0], 413)
        self.assertEqual(self.call('POST', '/say', 'a', raw='not json')[0], 400)
        self.assertEqual(self.call('POST', '/say', 'a', raw='[1]')[0], 400)
        self.assertEqual(self.call('GET', '/wait?after=abc', 'a')[0], 400)
        self.assertEqual(self.call('GET', '/wait?after=-1', 'a')[0], 400)

    def test_thread_budget_and_reset(self):
        for _ in range(3):
            self.assertEqual(self.say('a', 'b')[0], 200)
        self.assertEqual(self.say('b', 'a')[0], 409)
        self.assertEqual(self.call('POST', '/admin/reset-thread', 'a', {'thread': 't'})[0], 403)
        self.assertEqual(self.call('POST', '/admin/reset-thread', 'root', {'thread': 't'})[0], 200)
        self.assertEqual(self.say('b', 'a')[0], 200)

    def test_pause_blocks_writes_not_reads(self):
        self.say('a', 'b')
        self.assertEqual(self.call('POST', '/admin/pause', 'a')[0], 403)
        self.assertEqual(self.call('POST', '/admin/pause', 'root')[0], 200)
        self.assertEqual(self.say('a', 'b')[0], 423)
        self.assertEqual(self.call('GET', '/messages', 'b')[0], 200)
        self.assertEqual(self.call('POST', '/admin/resume', 'root')[0], 200)
        self.assertEqual(self.say('a', 'b')[0], 200)

    def test_task_overlap_over_http(self):
        self.assertEqual(self.call('POST', '/task', 'a', {'title': 'x', 'files': ['relay/x.py']})[0], 200)
        self.assertEqual(self.call('POST', '/task', 'b', {'title': 'y', 'files': ['relay']})[0], 409)
        self.assertEqual(self.call('POST', '/task', 'b', {'title': 'y', 'files': ['../etc']})[0], 400)
        task = self.call('GET', '/tasks', 'b')[1]['tasks'][0]
        self.assertEqual(self.call('POST', '/done', 'b', {'id': task['id'], 'branch': 'b/x'})[0], 403)
        self.assertEqual(self.call('POST', '/done', 'a', {'id': task['id'], 'branch': 'a/x'})[0], 200)

    def test_admin_route_aliases_not_reachable(self):
        for who in ('a', 'eye'):
            for path in ('/admin/pause', '/admin_pause', '/admin-pause', '/admin/resume', '/admin_resume',
                         '/admin-resume', '/admin/reset-thread', '/admin_reset_thread', '/admin/reset_thread',
                         '/admin//pause', '/admin/pause/', '/ADMIN/pause'):
                status, _ = self.call('POST', path, who, {'thread': 't'})
                self.assertIn(status, (403, 404), (who, path))
        self.assertFalse(self.domain.is_paused())
        for path in ('/admin_pause', '/admin-pause', '/admin//pause', '/admin/pause/'):
            self.assertEqual(self.call('POST', path, 'root')[0], 404, path)
        self.assertEqual(self.call('GET', '/admin/pause', 'root')[0], 404)
        self.assertFalse(self.domain.is_paused())

    def raw_request(self, request):
        import socket
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as sock:
            sock.sendall(request)
            data = b''
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        return int(data.split(b' ', 2)[1])

    def test_malformed_input_never_500(self):
        for query in ('after=%C2%B2', 'after=' + '9' * 5000, 'after=-1', 'after=1.5', 'timeout=%C2%B2'):
            self.assertEqual(self.call('GET', f'/wait?{query}', 'a')[0], 400, query)
        self.assertEqual(self.call('POST', '/say', 'a', raw='[' * 20000)[0], 400)
        auth = f"Authorization: Bearer {self.tokens['a']}\r\n".encode()
        base = b'POST /say HTTP/1.1\r\nHost: x\r\n' + auth
        self.assertEqual(self.raw_request(base + b'Content-Length: -1\r\n\r\n'), 400)
        self.assertEqual(self.raw_request(base + b'Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello'), 400)
        self.assertEqual(self.raw_request(base + b'Content-Length: abc\r\n\r\n'), 400)
        self.assertEqual(self.raw_request(base + b'Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n'), 400)

    def test_error_replies_survive_unread_bodies(self):
        big = json.dumps({'to': 'b', 'text': 'x' * 200000})
        self.assertEqual(self.call('POST', '/say', 'a', raw=big)[0], 413)
        self.assertEqual(self.call('POST', '/admin/pause', 'a', raw=big)[0], 403)
        self.assertEqual(self.call('POST', '/say', raw=big)[0], 401)

    def test_slow_client_times_out(self):
        import socket
        from relay import server
        self.assertEqual(server.SOCKET_TIMEOUT, 30)

    def test_wait_slots_and_budget_retry_after(self):
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.call('GET', '/wait?timeout=3', 'b')))
                   for _ in range(2)]
        for t in threads:
            t.start()
        time.sleep(0.5)
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.request('GET', '/wait?timeout=1', headers={'Authorization': f"Bearer {self.tokens['b']}"})
        resp = conn.getresponse()
        resp.read()
        self.assertEqual((resp.status, resp.getheader('retry-after')), (429, '5'))
        for t in threads:
            t.join(10)
        self.assertEqual(sorted(r[0] for r in results), [200, 200])
        self.say('a', 'b', thread='u')
        self.domain.hourly_messages = 1
        conn.request('POST', '/say', body=json.dumps({'to': 'b', 'thread': 'u', 'text': 'x'}),
                     headers={'Authorization': f"Bearer {self.tokens['a']}"})
        resp = conn.getresponse()
        resp.read()
        self.assertEqual((resp.status, resp.getheader('retry-after')), (429, '60'))

    def test_revocation_during_wait(self):
        result = {}
        t = threading.Thread(target=lambda: result.update(r=self.call('GET', '/wait?timeout=30', 'b')))
        t.start()
        time.sleep(0.5)
        self.domain.revoke('b')
        t.join(8)
        self.assertFalse(t.is_alive())
        self.assertEqual(result['r'][0], 403)
        self.assertEqual(self.call('GET', '/status', 'b')[0], 401)

    def test_roles_enforced_per_route(self):
        self.assertEqual(self.call('GET', '/wait?timeout=0', 'eye')[0], 403)
        self.assertEqual(self.call('GET', '/wait?timeout=0', 'root')[0], 403)
        self.assertEqual(self.call('POST', '/task', 'eye', {'title': 'x', 'files': ['f']})[0], 403)

    def test_observer_cannot_write(self):
        self.assertEqual(self.say('eye', 'a')[0], 403)

    def test_unknown_route_and_rate_limit(self):
        self.assertEqual(self.call('GET', '/nope', 'a')[0], 404)
        codes = [self.call('GET', '/status', 'a')[0] for _ in range(40)]
        self.assertIn(429, codes)

    def test_restart_replay(self):
        self.say('a', 'b', 'persist')
        path = self.store.connection.execute('PRAGMA database_list').fetchone()[2]
        store2 = Store(path)
        self.addCleanup(store2.close)
        rows = Domain(store2).fetch({'name': 'b', 'role': 'agent'}, 0)
        self.assertEqual([m['text'] for m in rows], ['persist'])


if __name__ == '__main__':
    unittest.main()
