"""HTTP layer: authentication, limits, envelopes and long polling over relay.domain."""
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .auth import authenticate
from .domain import DomainError

MAX_BODY = 64 * 1024
MAX_WAIT = 60
MAX_WAITS_PER_AGENT = 2
DRAIN_LIMIT = 1024 * 1024
SOCKET_TIMEOUT = 30
BUCKET_BURST, BUCKET_RATE = 20, 5.0


class Busy(DomainError):
    """429 with a retry hint in seconds."""

    def __init__(self, message, retry_after):
        super().__init__(429, message)
        self.retry_after = retry_after


class Hub:
    """Shared state for handlers: domain, long-poll wake-ups, wait slots, rate buckets."""

    def __init__(self, domain):
        self.domain = domain
        self.cv = threading.Condition()
        self.waits, self.buckets = {}, {}

    def take(self, name):
        """Token bucket; returns seconds to wait when empty, else 0."""
        now = time.monotonic()
        with self.cv:
            tokens, last = self.buckets.get(name, (BUCKET_BURST, now))
            tokens = min(BUCKET_BURST, tokens + (now - last) * BUCKET_RATE)
            if tokens < 1:
                self.buckets[name] = (tokens, now)
                return (1 - tokens) / BUCKET_RATE
            self.buckets[name] = (tokens - 1, now)
            return 0

    def wait_for(self, principal, after, timeout):
        """Return (messages from others, new cursor), blocking up to timeout seconds."""
        name, end = principal['name'], time.monotonic() + timeout
        with self.cv:
            if self.waits.get(name, 0) >= MAX_WAITS_PER_AGENT:
                raise Busy('too many concurrent waits', 5)
            self.waits[name] = self.waits.get(name, 0) + 1
        try:
            while True:
                rows = self.domain.fetch(principal, after, 100)
                if rows:
                    after = rows[-1]['id']
                    mine = [m for m in rows if m['from'] != name]
                    if mine:
                        return mine, after
                    continue
                left = end - time.monotonic()
                if left <= 0:
                    return [], after
                with self.cv:
                    self.cv.wait(min(left, 2.0))
        finally:
            with self.cv:
                self.waits[name] -= 1

    def wake(self):
        with self.cv:
            self.cv.notify_all()


ANY = frozenset({'agent', 'observer', 'admin'})
AGENT = frozenset({'agent'})
WATCH = frozenset({'observer', 'admin'})
ADMIN = frozenset({'admin'})

# Exact (method, path) -> (handler name, allowed roles). Authorization lives only here.
ROUTES = {
    ('GET', '/wait'): ('get_wait', AGENT),
    ('GET', '/messages'): ('get_messages', ANY),
    ('GET', '/tasks'): ('get_tasks', ANY),
    ('GET', '/status'): ('get_status', ANY),
    ('GET', '/observe'): ('get_observe', WATCH),
    ('POST', '/say'): ('post_say', AGENT),
    ('POST', '/task'): ('post_task', AGENT),
    ('POST', '/done'): ('post_done', AGENT),
    ('POST', '/release'): ('post_release', AGENT),
    ('POST', '/admin/pause'): ('post_admin_pause', ADMIN),
    ('POST', '/admin/resume'): ('post_admin_resume', ADMIN),
    ('POST', '/admin/reset-thread'): ('post_admin_reset_thread', ADMIN),
}


def _int(q, key, default, lo=0, hi=2**63 - 1):
    raw = q.get(key, [str(default)])[0]
    if not re.fullmatch(r'[0-9]{1,18}', raw) or not lo <= int(raw) <= hi:
        raise DomainError(400, f'invalid {key}')
    return int(raw)


def make_handler(hub):
    domain = hub.domain

    class Handler(BaseHTTPRequestHandler):
        timeout = SOCKET_TIMEOUT
        unread = 0

        def log_message(self, *args):
            pass

        def reply(self, code, body, headers=(), ctype='application/json'):
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('content-type', ctype)
            self.send_header('content-length', str(len(data)))
            self.send_header('cache-control', 'no-store')
            self.send_header('x-content-type-options', 'nosniff')
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def fail(self, code, message, headers=()):
            self.reply(code, {'error': message, 'code': code}, headers)

        def framing(self):
            """Validate request framing; returns the declared body length (0 for GET)."""
            if self.headers.get('transfer-encoding') is not None:
                raise DomainError(400, 'chunked or encoded request bodies are not supported')
            raw = self.headers.get_all('content-length') or ['0']
            if len(raw) != 1 or not re.fullmatch(r'[0-9]{1,12}', raw[0].strip()):
                raise DomainError(400, 'invalid content-length')
            return int(raw[0])

        def body(self):
            length = self.unread
            if length > MAX_BODY:
                raise DomainError(413, 'request body too large')
            self.unread = 0
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise DomainError(400, 'request body shorter than content-length')
            try:
                data = json.loads(raw or b'{}')
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise DomainError(400, 'body must be valid JSON') from None
            if not isinstance(data, dict):
                raise DomainError(400, 'body must be a JSON object')
            return data

        def drain(self):
            """Discard an unread request body (bounded) so the error reply is not lost to a reset."""
            left, self.unread = self.unread, 0
            if left > DRAIN_LIMIT:
                self.close_connection = True
                return
            while left > 0:
                chunk = self.rfile.read(min(left, 65536))
                if not chunk:
                    break
                left -= len(chunk)

        def handle_request(self, method):
            self.unread = self.framing()
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if 'key' in q or 'token' in q:
                return self.fail(400, 'credentials in the URL are not accepted; use the Authorization header')
            who = authenticate(domain, self.headers.get('authorization'))
            if who is None:
                return self.fail(401, 'missing or invalid token', [('www-authenticate', 'Bearer')])
            delay = hub.take(who['name'])
            if delay:
                return self.fail(429, 'rate limit exceeded', [('retry-after', str(int(delay) + 1))])
            entry = ROUTES.get((method.upper(), url.path))
            if entry is None:
                return self.fail(404, 'not found')
            handler, roles = entry
            if who['role'] not in roles:
                return self.fail(403, f"{' or '.join(sorted(roles))} role required")
            route = getattr(self, handler)
            body = self.body() if method == 'post' else {}
            if 'from' in body and body['from'] != who['name']:
                return self.fail(400, 'from does not match authenticated identity')
            route(who, q, body)

        def dispatch(self, method):
            try:
                try:
                    self.handle_request(method)
                finally:
                    self.drain()
            except DomainError as err:
                retry = getattr(err, 'retry_after', 60 if err.code == 429 else None)
                self.fail(err.code, err.message, [('retry-after', str(retry))] if retry else ())
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True
            except Exception:
                self.fail(500, 'internal error')

        def do_GET(self):
            self.dispatch('get')

        def do_POST(self):
            self.dispatch('post')

        # --- routes: get_<path> / post_<path>, handler(who, query, body) ---
        def get_wait(self, who, q, _body):
            after = _int(q, 'after', 0)
            msgs, cursor = hub.wait_for(who, after, _int(q, 'timeout', MAX_WAIT, 0, MAX_WAIT))
            self.reply(200, {'messages': msgs, 'cursor': cursor, 'timeout': not msgs})

        def get_messages(self, who, q, _body):
            rows = domain.fetch(who, _int(q, 'after', 0), _int(q, 'limit', 100, 1, 1000))
            self.reply(200, {'messages': rows, 'cursor': rows[-1]['id'] if rows else _int(q, 'after', 0)})

        def get_tasks(self, who, q, _body):
            self.reply(200, {'tasks': domain.tasks()})

        def get_status(self, who, q, _body):
            self.reply(200, domain.status())

        def get_observe(self, who, q, _body):
            rows = domain.fetch(who, 0, 1000)
            text = '\n\n'.join(f"[{m['id']}] {m['from']} -> {m['to']} ({m['thread']}): {m['text']}" for m in rows)
            self.reply(200, text, ctype='text/plain; charset=utf-8')

        def post_say(self, who, q, body):
            if not isinstance(body.get('text'), str):
                raise DomainError(400, 'text required')
            msg = domain.post(who['name'], body.get('to'), body.get('thread', 'main'), body['text'])
            hub.wake()
            self.reply(200, {'id': msg['id']})

        def post_task(self, who, q, body):
            self.reply(200, domain.create_task(who['name'], body.get('title'), body.get('files')))

        def post_done(self, who, q, body):
            self.reply(200, domain.finish_task(who['name'], body.get('id'), body.get('branch')))

        def post_release(self, who, q, body):
            self.reply(200, domain.release_task(who['name'], body.get('id')))

        def post_admin_pause(self, who, q, body):
            domain.pause()
            self.reply(200, {'paused': True})

        def post_admin_resume(self, who, q, body):
            domain.resume()
            hub.wake()
            self.reply(200, {'paused': False})

        def post_admin_reset_thread(self, who, q, body):
            domain.reset_thread(body.get('thread'))
            self.reply(200, {'ok': True})

    return Handler


def make_server(domain, host='127.0.0.1', port=8765):
    server = ThreadingHTTPServer((host, port), make_handler(Hub(domain)))
    server.daemon_threads = True
    return server
