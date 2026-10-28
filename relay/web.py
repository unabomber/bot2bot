"""Browser admin UI: static app, cookie-session login and the /ui/api allowlist.

Cookie sessions reach ONLY the routes below. Bearer routes never read cookies, and nothing here returns
message text (metadata only). Request guards live in web_security; session state lives in the domain."""
import json
import os
import re

from .auth import hash_token
from .domain import DomainError

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
# Fixed allowlist: URL path -> (file, content type). Nothing else is ever read from disk.
_STATIC = {
    '/ui': ('index.html', 'text/html; charset=utf-8'),
    '/ui/': ('index.html', 'text/html; charset=utf-8'),
    '/ui/app.js': ('app.js', 'text/javascript; charset=utf-8'),
    '/ui/app.css': ('app.css', 'text/css; charset=utf-8'),
}
_TOKEN = re.compile(r'[A-Za-z0-9_-]{20,128}')
ROOM = r'(?P<room>[A-Za-z0-9_-]{1,64})'
NAME = r'(?P<name>[A-Za-z0-9_-]{1,64})'
API = [(m, re.compile('/ui/api/' + p), h) for m, p, h in [
    ('GET', r'session', 'session'),
    ('POST', r'logout', 'logout'),
    ('POST', r'logout-all', 'logout_all'),
    ('GET', r'rooms', 'rooms'),
    ('POST', r'rooms', 'create_room'),
    ('POST', rf'rooms/{ROOM}/close', 'close'),
    ('POST', rf'rooms/{ROOM}/reopen', 'reopen'),
    ('POST', rf'rooms/{ROOM}/reset-thread', 'reset_thread'),
    ('POST', rf'rooms/{ROOM}/inject', 'inject'),
    ('POST', rf'rooms/{ROOM}/members', 'add_member'),
    ('POST', rf'rooms/{ROOM}/members/{NAME}/revoke', 'revoke_member'),
    ('POST', rf'rooms/{ROOM}/members/{NAME}/rotate', 'rotate_member'),
    ('GET', rf'rooms/{ROOM}/members', 'members'),
    ('GET', rf'rooms/{ROOM}/monitor', 'monitor'),
    ('GET', rf'rooms/{ROOM}/stats', 'stats'),
]]


class Web:
    """Immutable shared state (static assets, guards, hub). Holds NO per-request state: every request gets its own
    _Request, because the server handles requests on concurrent threads."""

    def __init__(self, hub, security):
        self.hub, self.domain, self.sec = hub, hub.domain, security
        self.files = {}
        for path, (name, ctype) in _STATIC.items():
            with open(os.path.join(STATIC_DIR, name), 'rb') as f:
                self.files[path] = (f.read(), ctype)

    def dispatch(self, h, method, path, q, int_arg):
        return _Request(self, h, int_arg).run(method, path, q)


class _Request:
    def __init__(self, web, h, int_arg):
        self.web, self.h, self.int_arg = web, h, int_arg
        self.hub, self.domain, self.sec = web.hub, web.domain, web.sec
        self.sid = self.info = self.admin = None

    # ---- one instance per request ----
    def run(self, method, path, q):
        h = self.h
        self.sec.check_host(h.headers)
        if method == 'GET' and path in self.web.files:
            data, ctype = self.web.files[path]
            return h.reply(200, data, self.sec.headers(), ctype)
        if method == 'POST' and path == '/ui/login':
            return self.login()
        if path.startswith('/ui/api/'):
            for m, pattern, handler in API:
                found = pattern.fullmatch(path) if m == method else None
                if found:
                    return self.api(handler, found.groupdict(), q, method)
        return self.reply_json(404, {'error': 'not found', 'code': 404})

    def reply_json(self, code, body, extra=()):
        self.h.reply(code, body, [*self.sec.headers(), *extra])

    def login(self):
        self.sec.check_request(self.h.headers, mutation=True)
        body = self.h.body()
        token = body.get('token')
        # Every submitted value is hashed and goes through session_create, so malformed guesses are throttled too.
        # Anything that is not a plausible credential (wrong type, odd characters, lone surrogates) is counted as a failed
        # attempt using the hash of '', so it can neither crash the request nor dodge the persisted throttle.
        if not (isinstance(token, str) and _TOKEN.fullmatch(token)):
            token = ''
        made = self.domain.session_create(hash_token(token), self.h.client_address[0])
        cookie = self.sec.session_cookie(made['session'])
        self.reply_json(200, {'csrf': made['csrf'], 'expires_at': made['expires_at']}, [('set-cookie', cookie)])

    def api(self, handler, params, q, method):
        mutation = method == 'POST'
        self.sec.check_request(self.h.headers, mutation=mutation)
        sid = self.sec.cookie_session(self.h.headers)
        if sid is None:
            return self.reply_json(401, {'error': 'not signed in', 'code': 401})
        csrf_values = self.h.headers.get_all('x-csrf') or []
        if len(csrf_values) > 1:
            raise DomainError(403, 'ambiguous CSRF header')
        csrf = csrf_values[0] if csrf_values else None
        info = self.domain.session_validate(sid, csrf, mutation=mutation)
        if info is None:
            return self.reply_json(401, {'error': 'session expired', 'code': 401},
                                   [('set-cookie', self.sec.clear_cookie())])
        delay = self.hub.take(('ui', info['principal']['name']))
        if delay:
            return self.reply_json(429, {'error': 'rate limit exceeded', 'code': 429}, [('retry-after', str(int(delay) + 1))])
        self.sid, self.info, self.admin = sid, info, info['principal']
        body = self.h.body() if mutation else {}
        getattr(self, 'api_' + handler)(q, body, **params)

    # ---- /ui/api handlers (admin principal from the session; metadata only) ----
    def api_session(self, q, body):
        self.reply_json(200, {'name': self.admin['name'], 'csrf': self.info['csrf'], 'expires_at': self.info['expires_at']})

    def api_logout(self, q, body):
        self.domain.session_revoke(self.sid)
        self.reply_json(200, {'ok': True}, [('set-cookie', self.sec.clear_cookie())])

    def api_logout_all(self, q, body):
        count = self.domain.session_revoke_all(self.sid)
        self.reply_json(200, {'revoked': count}, [('set-cookie', self.sec.clear_cookie())])

    def api_rooms(self, q, body):
        self.reply_json(200, {'rooms': self.domain.list_rooms(self.admin)})

    def api_create_room(self, q, body):
        members = body.get('members', [])
        if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
            raise DomainError(400, 'members must be a list of names')
        self.reply_json(200, self.domain.create_room(self.admin, body.get('name'), members))

    def api_close(self, q, body, room):
        self.reply_json(200, self.domain.set_room_closed(self.admin, room, True))
        self.hub.wake()

    def api_reopen(self, q, body, room):
        self.reply_json(200, self.domain.set_room_closed(self.admin, room, False))

    def api_reset_thread(self, q, body, room):
        thread = body.get('thread')
        if type(thread) is not int or thread < 1:
            raise DomainError(400, 'thread must be the public thread number (integer)')  # labels are content; never accepted here
        self.domain.reset_room_thread(self.admin, room, thread)
        self.reply_json(200, {'ok': True})

    def api_inject(self, q, body, room):
        to, text = body.get('to'), body.get('text')
        if not (to == '*' or (isinstance(to, list) and all(isinstance(t, str) for t in to))) or not isinstance(text, str):
            raise DomainError(400, "to ('*' or names) and text required")
        env = self.domain.inject(self.admin, room, to, body.get('thread', 'human'), text)
        self.hub.wake()
        self.reply_json(200, {'id': env['id']})  # never echo the message text back

    def api_add_member(self, q, body, room):
        token = self.domain.mint_member(self.admin, room, body.get('name'), body.get('role', 'agent'))
        self.reply_json(200, {'name': body.get('name'), 'token': token})

    def api_revoke_member(self, q, body, room, name):
        self.domain.revoke_member(self.admin, room, name)
        self.hub.wake()
        self.reply_json(200, {'ok': True})

    def api_rotate_member(self, q, body, room, name):
        token = self.domain.rotate_member(self.admin, room, name)
        self.hub.wake()
        self.reply_json(200, {'name': name, 'token': token})

    def api_members(self, q, body, room):
        members = self.domain.members(self.admin, room)
        for member in members:
            member['waiting'] = self.hub.waiting(room, member['name'])
        self.reply_json(200, {'members': members})

    def api_monitor(self, q, body, room):
        after = self.int_arg(q, 'after', 0)
        rows = self.domain.monitor(self.admin, room, after, self.int_arg(q, 'limit', 100, 1, 500))
        self.reply_json(200, {'events': rows, 'cursor': rows[-1]['id'] if rows else after})

    def api_stats(self, q, body, room):
        self.reply_json(200, self.domain.stats(self.admin, room))
