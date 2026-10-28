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

    def test_frontend_state_is_view_local_and_layout_is_responsive(self):
        js = self.request('GET', '/ui/app.js')[1]
        css = self.request('GET', '/ui/app.css')[1]
        self.assertNotIn('state.after', js)                 # feed cursor must not be shared across room views
        self.assertIn('view !== state.view', js)            # stale async completions are ignored
        self.assertIn('busy', js)                           # polls never overlap
        self.assertIn('[hidden] { display:none !important; }', css)
        self.assertNotIn('nth-child', css)                  # no hidden table columns on narrow screens
        self.assertIn('overflow-x:auto', css)
        self.assertIn('window.isSecureContext', js)          # clipboard fallback for plain-HTTP pages
        self.assertIn('rows.replaceChildren', js)            # polling swaps table rows only; forms keep what is typed
        self.assertIn('membersBody.replaceChildren', js)
        self.assertIn("type: 'number'", js)                 # thread reset takes the public thread number, never a label
        self.assertIn('e.thread_no', js)
        self.assertIn('a { color: var(--accent); }', css)

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
        reset = lambda body: self.api('POST', 'rooms/alpha/reset-thread', s, body)[0]
        for bad in ({'thread': 'nothing'}, {'thread': 1}, {'thread_no': 'x'}, {'thread_no': True}, {'thread_no': 0}, {'thread_no': 1, 'thread': 'label'}, {}):
            self.assertEqual(reset(bad), 400, bad)          # labels are content: the UI accepts public numbers only
        self.assertEqual(reset({'thread_no': 999}), 404)
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

    def test_reset_thread_by_public_number(self):
        s = self.session()
        made = self.api('POST', 'rooms', s, {'name': 'alpha', 'members': ['a', 'b']})[1]
        token = {m['name']: m['token'] for m in made['members']}['a']
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.request('POST', '/rooms/alpha/say', body=json.dumps({'to': ['b'], 'thread': 'some-label', 'text': 'x'}),
                     headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(conn.getresponse().status, 200)
        number = self.api('GET', 'rooms/alpha/monitor', s)[1]['events'][0]['thread_no']
        self.assertEqual(self.api('POST', 'rooms/alpha/reset-thread', s, {'thread_no': number})[0], 200)

    def test_sync_panel_api_is_metadata_only_and_admin_controls_work(self):
        s = self.session()
        made = self.api('POST', 'rooms', s, {'name': 'alpha', 'members': ['a', 'b', 'c']})[1]
        tokens = {m['name']: m['token'] for m in made['members']}

        def agent(who, method, path, body=None):
            conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
            conn.request(method, path, body=json.dumps(body) if body is not None else None,
                         headers={'Authorization': f'Bearer {tokens[who]}'})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read().decode())
        status, proposed = agent('a', 'POST', '/rooms/alpha/state/propose', {'base_version': 0, 'state': 'PRIVATE-STATE-TEXT'})
        self.assertEqual(status, 200)
        self.assertEqual(agent('a', 'POST', '/rooms/alpha/status', {'state_version': 0, 'waiting_on': 'b', 'reason': 'PRIVATE-REASON-TEXT'})[0], 200)
        status, view = self.api('GET', 'rooms/alpha/sync', s)
        self.assertEqual(status, 200)
        self.assertTrue(view['round_open'])
        self.assertEqual(view['waiting_on']['a'], 'b')
        blob = json.dumps(view)
        self.assertNotIn('PRIVATE-STATE-TEXT', blob)
        self.assertNotIn('PRIVATE-REASON-TEXT', blob)
        self.assertEqual(self.api('POST', 'rooms/alpha/sync/abort', s)[0], 200)
        self.assertFalse(self.api('GET', 'rooms/alpha/sync', s)[1]['round_open'])
        status, cfg = self.api('POST', 'rooms/alpha/sync/settings', s, {'strict': True, 'stall_seconds': 30, 'turn': 'a'})
        self.assertEqual((status, cfg['strict'], cfg['turn']), (200, True, 'a'))
        self.assertEqual(self.api('POST', 'rooms/alpha/sync/settings', s, {'bogus': 1})[0], 400)
        self.assertEqual(self.api('POST', 'rooms/alpha/sync/settings', s, {'turn': None})[1]['turn'], None)
        agent('a', 'POST', '/rooms/alpha/state/propose', {'base_version': 0, 'state': 'x'})
        self.assertEqual(self.api('POST', 'rooms/alpha/sync/remove', s, {'name': 'c'})[0], 200)
        # CSRF still guards the new mutations, and nothing here is reachable with a bearer or without a session
        cookie, csrf = s
        self.assertEqual(self.request('POST', '/ui/api/rooms/alpha/sync/abort', {}, cookie=cookie, csrf='wrong')[0], 403)
        self.assertEqual(self.request('GET', '/ui/api/rooms/alpha/sync')[0], 401)
        self.assertEqual(self.api('GET', 'rooms/alpha/state', s)[0], 404)          # shared state text has no UI route

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

    def test_concurrent_requests_do_not_share_state(self):
        # Two admins inside list_rooms at the same moment (barrier). Per-request state must stay separate:
        # each response must carry its own admin name and reach its own connection.
        second = self.domain.mint_agent('root2', 'admin')
        one = self.session()
        status, cookie, csrf, _ = self.login(second)
        two = (cookie, csrf)
        barrier = threading.Barrier(2)

        def fake_list_rooms(admin):
            barrier.wait(timeout=10)
            return [{'name': 'seen-by-' + admin['name']}]
        self.domain.list_rooms = fake_list_rooms
        results = {}

        def call(key, session):
            results[key] = self.api('GET', 'rooms', session)
        threads = [threading.Thread(target=call, args=('root', one)), threading.Thread(target=call, args=('root2', two))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        self.assertEqual(results['root'][1]['rooms'][0]['name'], 'seen-by-root')
        self.assertEqual(results['root2'][1]['rooms'][0]['name'], 'seen-by-root2')

    def test_concurrent_logout_all_only_affects_own_admin(self):
        second = self.domain.mint_agent('root2', 'admin')
        one, other = self.session(), self.session()
        _, cookie, csrf, _ = self.login(second)
        two = (cookie, csrf)
        results = {}
        barrier = threading.Barrier(2)
        real = self.domain.session_revoke_all

        def synced(session):
            barrier.wait(timeout=10)
            return real(session)
        self.domain.session_revoke_all = synced
        threads = [threading.Thread(target=lambda k=k, s=s: results.update({k: self.api('POST', 'logout-all', s)}))
                   for k, s in (('root', one), ('root2', two))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        self.assertEqual((results['root'][1]['revoked'], results['root2'][1]['revoked']), (2, 1))
        self.assertEqual(self.api('GET', 'session', other)[0], 401)

    def test_malformed_login_tokens_are_throttled_too(self):
        codes = [self.request('POST', '/ui/login', {'token': 'x'})[0] for _ in range(7)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[-1], 429)

    def test_unencodable_login_tokens_are_counted_not_500(self):
        codes = [self.request('POST', '/ui/login', raw='{"token":"\\ud800"}')[0] for _ in range(7)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[-1], 429)

    def test_query_strings_do_not_dodge_error_headers(self):
        for path, kw in (('/ui?x=1', {'headers': {'Host': 'evil.example'}}), ('/ui/nope?x=1', {}), ('/ui/api/rooms?y=2', {})):
            status, _, resp = self.request('GET', path, **kw)
            self.assertGreaterEqual(status, 400, path)
            self.assertIn("default-src 'none'", resp.getheader('Content-Security-Policy') or '', path)

    def test_error_responses_carry_security_headers(self):
        cases = [self.request('GET', '/ui/nope'), self.request('GET', '/ui', headers={'Host': 'evil.example'}),
                 self.request('POST', '/ui/login', {'token': 'x' * 43}),
                 self.request('POST', '/ui/login', raw='not json'),
                 self.request('GET', '/ui/api/rooms'),
                 self.request('POST', '/ui/login', raw='', headers={'Content-Length': '-1'})]  # header-only rejection: no body to leave unread
        s = self.session()
        cases.append(self.request('POST', '/ui/api/rooms', {'name': 'q'}, cookie=s[0], csrf='wrong'))
        for status, _, resp in cases:
            self.assertGreaterEqual(status, 400)
            self.assertIn("default-src 'none'", resp.getheader('Content-Security-Policy') or '', status)
            self.assertEqual(resp.getheader('X-Frame-Options'), 'DENY')
            self.assertEqual(resp.getheader('Referrer-Policy'), 'no-referrer')

    def test_duplicate_csrf_headers_rejected(self):
        cookie, csrf = self.session()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.putrequest('POST', '/ui/api/rooms', skip_host=True)
        for k, v in (('Host', f'127.0.0.1:{self.port}'), ('Origin', self.origin), ('Content-Type', 'application/json'),
                     ('Cookie', f'b2b_session={cookie}'), ('X-CSRF', csrf), ('X-CSRF', csrf), ('Content-Length', '2')):
            conn.putheader(k, v)
        conn.endheaders(b'{}')
        self.assertEqual(conn.getresponse().status, 403)

    def test_wrong_method_and_unknown_api(self):
        s = self.session()
        self.assertEqual(self.api('GET', 'logout', s)[0], 404)
        self.assertEqual(self.api('GET', 'nope', s)[0], 404)
        self.assertEqual(self.api('POST', 'session', s, {})[0], 404)


if __name__ == '__main__':
    unittest.main()
