import http.client
import json
import os
import tempfile
import threading
import unittest

from relay.domain import Domain
from relay.server import make_server
from relay.store import Store

SECRET = 'SECRETPAYLOAD'


class WebTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), 'w.db'))
        self.domain = Domain(self.store)
        self.admin_token = self.domain.mint_agent('root', 'admin')
        self.server = make_server(self.domain, '127.0.0.1', 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.origin = f'http://127.0.0.1:{self.port}'
        self.addCleanup(self.store.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, cookie=None, csrf=None, origin='default', headers=None, raw=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        h = {'Host': f'127.0.0.1:{self.port}'}
        if method == 'POST':
            h['Content-Type'] = 'application/json'
            h['Origin'] = self.origin if origin == 'default' else origin
        if cookie:
            h['Cookie'] = f'b2b_session={cookie}'
        if csrf:
            h['X-CSRF'] = csrf
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        data = raw if raw is not None else (json.dumps(body) if body is not None else None)
        conn.request(method, path, body=data, headers=h)
        resp = conn.getresponse()
        text = resp.read().decode()
        out = (resp.status, text, resp)
        conn.close()
        return out

    def login(self, token=None, **kw):
        status, text, resp = self.request('POST', '/ui/login', {'token': token or self.admin_token}, **kw)
        if status != 200:
            return status, None, None, text
        cookie = resp.getheader('Set-Cookie').split(';')[0].split('=', 1)[1]
        return status, cookie, json.loads(text)['csrf'], text

    def session(self):
        status, cookie, csrf, _ = self.login()
        self.assertEqual(status, 200)
        return cookie, csrf

    def api(self, method, path, session, body=None, **kw):
        cookie, csrf = session
        status, text, resp = self.request(method, '/ui/api/' + path, body, cookie=cookie, csrf=csrf, **kw)
        try:
            return status, json.loads(text)
        except ValueError:
            return status, text

    # ---- static and headers ----
    def test_static_pages_and_headers(self):
        for path, marker in (('/ui', b'<script'), ('/ui/', b'<script'), ('/ui/app.js', b'fetch('), ('/ui/app.css', b'--bg')):
            status, text, resp = self.request('GET', path)
            self.assertEqual(status, 200, path)
            self.assertIn(marker.decode(), text)
            self.assertIn("script-src 'self'", resp.getheader('Content-Security-Policy'))
            self.assertIn("frame-ancestors 'none'", resp.getheader('Content-Security-Policy'))
            self.assertEqual(resp.getheader('X-Frame-Options'), 'DENY')
            self.assertEqual(resp.getheader('X-Content-Type-Options'), 'nosniff')
            self.assertIn('no-store', resp.getheader('Cache-Control'))
        self.assertIsNone(self.request('GET', '/ui/app.js')[2].getheader('Access-Control-Allow-Origin'))

    def test_js_never_uses_innerhtml_and_page_has_no_inline_script(self):
        js = self.request('GET', '/ui/app.js')[1]
        for banned in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval('):
            self.assertTrue(banned not in js, banned)
        html = self.request('GET', '/ui')[1]
        self.assertNotIn('onclick=', html)
        self.assertNotIn('style=', html)
        self.assertEqual(html.count('<script'), 1)
        self.assertIn('src="/ui/app.js"', html)

    def test_static_allowlist_and_traversal(self):
        for path in ('/ui/../relay/server.py', '/ui/%2e%2e/relay/server.py', '/ui/static/app.js', '/ui/index.html',
                     '/ui/app.js/', '/ui/relay/web.py', '/ui/api', '/ui/x'):
            self.assertEqual(self.request('GET', path)[0], 404, path)

    def test_host_header_must_match_configured_origin(self):
        self.assertIn(self.request('GET', '/ui', headers={'Host': 'evil.example'})[0], (400, 403, 421))

    def test_ui_can_be_disabled_and_needs_origin_off_loopback(self):
        server = make_server(self.domain, '127.0.0.1', 0, ui=False)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        conn = http.client.HTTPConnection('127.0.0.1', server.server_address[1], timeout=5)
        conn.request('GET', '/ui')
        self.assertEqual(conn.getresponse().status, 404)
        with self.assertRaises(ValueError):
            make_server(self.domain, '0.0.0.0', 0)

    # ---- login ----
    def test_login_sets_hardened_cookie(self):
        status, text, resp = self.request('POST', '/ui/login', {'token': self.admin_token})
        self.assertEqual(status, 200)
        cookie = resp.getheader('Set-Cookie')
        for attr in ('HttpOnly', 'SameSite=Strict', 'Path=/ui'):
            self.assertIn(attr, cookie)
        self.assertNotIn('Secure', cookie)            # configured origin is http
        body = json.loads(text)
        self.assertTrue(body['csrf'])
        self.assertNotIn(self.admin_token, text)
        self.assertNotIn(self.admin_token, cookie)

    def test_login_failures_are_generic(self):
        agent = self.domain.mint_agent('plain', 'agent')
        for token in ('x' * 43, agent, '', 'short'):
            status, text, _ = self.request('POST', '/ui/login', {'token': token})
            self.assertEqual(status, 401, token)
            self.assertNotIn(token or 'zzz-none', text)
        self.assertEqual(self.request('POST', '/ui/login', raw='not json')[0], 400)
        self.assertEqual(self.request('POST', '/ui/login', {'token': 5})[0], 401)

    def test_login_requires_same_origin_json_post(self):
        for kw in ({'origin': 'http://evil.example'}, {'origin': 'null'}, {'origin': None},
                   {'headers': {'Content-Type': 'text/plain'}}, {'headers': {'Sec-Fetch-Site': 'cross-site'}}):
            status = self.request('POST', '/ui/login', {'token': self.admin_token}, **kw)[0]
            self.assertIn(status, (400, 403, 415), kw)
        self.assertEqual(self.request('GET', '/ui/login')[0], 404)

    def test_login_throttle(self):
        codes = [self.request('POST', '/ui/login', {'token': 'x' * 43})[0] for _ in range(8)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[-1], 429)
        status, _, resp = self.request('POST', '/ui/login', {'token': 'x' * 43})
        self.assertEqual(status, 429)
        self.assertTrue(resp.getheader('Retry-After'))

    # ---- sessions, CSRF, allowlist ----
    def test_api_requires_session(self):
        self.assertEqual(self.request('GET', '/ui/api/session')[0], 401)
        self.assertEqual(self.request('GET', '/ui/api/rooms', cookie='x' * 43)[0], 401)
        self.assertEqual(self.request('GET', '/ui/api/rooms', headers={'Authorization': f'Bearer {self.admin_token}'})[0], 401)

    def test_session_returns_same_csrf_after_reload(self):
        cookie, csrf = self.session()
        again = self.api('GET', 'session', (cookie, csrf))[1]
        self.assertEqual((again['name'], again['csrf']), ('root', csrf))
        second = self.api('GET', 'session', (cookie, None))[1]['csrf']
        self.assertEqual(second, csrf)

    def test_csrf_origin_and_content_type_enforced_without_mutation(self):
        cookie, csrf = self.session()
        body = {'name': 'blocked', 'members': ['a']}
        for kw in ({'csrf': None}, {'csrf': 'wrong'}, {'origin': 'http://evil.example'}, {'origin': None},
                   {'headers': {'Content-Type': 'text/plain'}}, {'headers': {'Sec-Fetch-Site': 'cross-site'}}):
            args = {'cookie': cookie, 'csrf': csrf}
            args.update(kw)
            status = self.request('POST', '/ui/api/rooms', body, **args)[0]
            self.assertIn(status, (400, 401, 403, 415), kw)
        names = [r['name'] for r in self.domain.list_rooms({'name': 'root', 'role': 'admin', 'room': None, 'generation': 1})]
        self.assertNotIn('blocked', names)
        self.assertEqual(self.api('POST', 'rooms', (cookie, csrf), body)[0], 200)

    def test_cookie_never_reaches_bearer_or_content_routes(self):
        cookie, csrf = self.session()
        self.api('POST', 'rooms', (cookie, csrf), {'name': 'alpha', 'members': ['a', 'b']})
        for path in ('/status', '/tasks', '/messages', '/observe', '/rooms/alpha/messages', '/rooms/alpha/monitor', '/admin/rooms'):
            self.assertEqual(self.request('GET', path, cookie=cookie)[0], 401, path)
        self.assertEqual(self.request('POST', '/admin/rooms/alpha/inject', {'to': '*', 'text': 'x'}, cookie=cookie, csrf=csrf)[0], 401)
        for path in ('rooms/alpha/messages', 'observe', 'tasks', 'messages', 'rooms/alpha/wait', 'rooms/alpha/say',
                     'admin/pause', 'status', 'rooms/alpha/tasks'):
            self.assertEqual(self.api('GET', path, (cookie, csrf))[0], 404, path)
        for path in ('admin/pause', 'admin/resume', 'say', 'rooms/alpha/say', 'task', 'rooms/alpha/task'):
            self.assertEqual(self.api('POST', path, (cookie, csrf), {})[0], 404, path)

    def test_admin_actions_via_ui(self):
        s = self.session()
        status, made = self.api('POST', 'rooms', s, {'name': 'alpha', 'members': ['a', 'b']})
        self.assertEqual(status, 200, made)
        tokens = {m['name']: m['token'] for m in made['members']}
        self.assertEqual(set(tokens), {'a', 'b'})
        self.assertEqual(self.api('POST', 'rooms/alpha/members', s, {'name': 'eye', 'role': 'monitor'})[0], 200)
        rooms = self.api('GET', 'rooms', s)[1]['rooms']
        self.assertEqual({r['name'] for r in rooms}, {'alpha', 'default'})
        self.assertEqual(self.api('POST', 'rooms/alpha/inject', s, {'to': '*', 'text': 'hi all'})[0], 200)
        self.assertEqual(self.api('POST', 'rooms/alpha/close', s)[0], 200)
        self.assertEqual(self.api('POST', 'rooms/alpha/reopen', s)[0], 200)
        status, rotated = self.api('POST', 'rooms/alpha/members/a/rotate', s)
        self.assertEqual(status, 200)
        self.assertNotEqual(rotated['token'], tokens['a'])
        self.assertEqual(self.api('POST', 'rooms/alpha/members/b/revoke', s)[0], 200)
        members = self.api('GET', 'rooms/alpha/members', s)[1]['members']
        self.assertEqual({m['name'] for m in members}, {'a', 'eye'})
        self.assertEqual(self.api('POST', 'rooms/alpha/reset-thread', s, {'thread': 'nothing'})[0], 404)
        self.assertEqual(self.api('POST', 'rooms', s, {'name': 'bad name'})[0], 400)
        self.assertEqual(self.api('POST', 'rooms/alpha/inject', s, {'to': 5, 'text': 'x'})[0], 400)

    def test_ui_api_never_returns_message_text(self):
        s = self.session()
        made = self.api('POST', 'rooms', s, {'name': 'alpha', 'members': ['a', 'b']})[1]
        tokens = {m['name']: m['token'] for m in made['members']}
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.request('POST', '/rooms/alpha/say', body=json.dumps({'to': ['b'], 'thread': 'secret-thread', 'text': SECRET}),
                     headers={'Authorization': f"Bearer {tokens['a']}"})
        self.assertEqual(conn.getresponse().status, 200)
        seen = []
        for method, path, body in (('POST', 'rooms/alpha/inject', {'to': '*', 'text': 'HUMANSECRET'}), ('GET', 'rooms', None),
                                   ('GET', 'rooms/alpha/members', None), ('GET', 'rooms/alpha/monitor?after=0', None),
                                   ('GET', 'rooms/alpha/stats', None), ('GET', 'session', None)):
            status, data = self.api(method, path, s, body)
            self.assertEqual(status, 200, path)
            seen.append(json.dumps(data))
        blob = ' '.join(seen)
        for secret in (SECRET, 'HUMANSECRET', 'secret-thread'):
            self.assertNotIn(secret, blob)
        events = json.loads(seen[3])['events']
        self.assertEqual([e['source'] for e in events], ['agent', 'human'])

    def test_logout_and_logout_all(self):
        one, two = self.session(), self.session()
        self.assertEqual(self.api('POST', 'logout', one)[0], 200)
        self.assertEqual(self.api('GET', 'session', one)[0], 401)
        self.assertEqual(self.api('GET', 'session', two)[0], 200)
        three = self.session()
        self.assertEqual(self.api('POST', 'logout-all', three)[0], 200)
        self.assertEqual(self.api('GET', 'session', two)[0], 401)
        self.assertEqual(self.api('GET', 'session', three)[0], 401)

    def test_revoking_admin_credential_kills_sessions(self):
        second = self.domain.mint_agent('root2', 'admin')
        status, cookie, csrf, _ = self.login(second)
        self.assertEqual(status, 200)
        self.assertEqual(self.api('GET', 'rooms', (cookie, csrf))[0], 200)
        self.domain.revoke('root2')
        self.assertEqual(self.api('GET', 'rooms', (cookie, csrf))[0], 401)

    def test_wrong_method_and_unknown_api(self):
        s = self.session()
        self.assertEqual(self.api('GET', 'logout', s)[0], 404)
        self.assertEqual(self.api('GET', 'nope', s)[0], 404)
        self.assertEqual(self.api('POST', 'session', s, {})[0], 404)


if __name__ == '__main__':
    unittest.main()
