"""HTTP layer: authentication, limits, envelopes and long polling over relay.domain."""
import json
import logging
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .auth import authenticate, bearer_token, hash_token
from .domain import DomainError

MAX_BODY = 64 * 1024
MAX_WAIT = 60
MAX_WAITS_PER_AGENT = 2
DRAIN_LIMIT = 1024 * 1024
DISCARD_SECONDS = 0.25
SOCKET_TIMEOUT = 30
BUCKET_BURST, BUCKET_RATE = 20, 5.0
DEFAULT_ROOM = 'default'
log = logging.getLogger('bot2bot.relay')
LEGACY_PREFIXES = ('legacy_', 'admin_pause', 'admin_resume')


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
        self.web = None

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

    def waiting(self, room, name):
        with self.cv:
            return self.waits.get((room, name), 0)

    def wait_for(self, room, name, fetch, closed, after, timeout):
        """Long poll. fetch(after) returns rows (it revalidates credentials on every call and
        raises DomainError on revocation); closed() says whether the room stopped accepting writes.
        Returns (messages from others, cursor, room_closed)."""
        key, end = (room, name), time.monotonic() + timeout
        with self.cv:
            if self.waits.get(key, 0) >= MAX_WAITS_PER_AGENT:
                raise Busy('too many concurrent waits', 5)
            self.waits[key] = self.waits.get(key, 0) + 1
        try:
            while True:
                rows = fetch(after)
                if rows:
                    after = rows[-1]['id']
                    mine = [m for m in rows if m['from'] != name]
                    if mine:
                        return mine, after, False
                    continue
                if closed():
                    return [], after, True
                left = end - time.monotonic()
                if left <= 0:
                    return [], after, False
                with self.cv:
                    self.cv.wait(min(left, 2.0))
        finally:
            with self.cv:
                self.waits[key] -= 1
                if not self.waits[key]:
                    del self.waits[key]

    def wake(self):
        with self.cv:
            self.cv.notify_all()


ANY = frozenset({'agent', 'observer', 'admin'})
CONTENT = ANY          # roles allowed to read message text (monitor is deliberately absent)
AGENT = frozenset({'agent'})
WATCH = frozenset({'observer', 'admin'})
METADATA = frozenset({'monitor', 'admin'})
ADMIN = frozenset({'admin'})

ROOM = r'(?P<room>[A-Za-z0-9_-]{1,64})'
NAME = r'(?P<name>[A-Za-z0-9_-]{1,64})'

# (method, exact path pattern, handler name, allowed roles). Authorization lives only here
# (and again inside the domain). Paths are matched with fullmatch; nothing is derived from the URL.
ROUTES = [(m, re.compile(p), h, r) for m, p, h, r in [
    # legacy single-room API: explicit aliases for room 'default'
    ('GET', r'/wait', 'legacy_wait', AGENT),
    ('GET', r'/messages', 'legacy_messages', CONTENT),
    ('GET', r'/tasks', 'legacy_tasks', ANY),
    ('GET', r'/status', 'legacy_status', ANY),
    ('GET', r'/observe', 'legacy_observe', WATCH),
    ('POST', r'/say', 'legacy_say', AGENT),
    ('POST', r'/task', 'legacy_task', AGENT),
    ('POST', r'/done', 'legacy_done', AGENT),
    ('POST', r'/release', 'legacy_release', AGENT),
    ('POST', r'/admin/pause', 'admin_pause', ADMIN),
    ('POST', r'/admin/resume', 'admin_resume', ADMIN),
    ('POST', r'/admin/reset-thread', 'legacy_reset_thread', ADMIN),
    # rooms
    ('POST', rf'/rooms/{ROOM}/say', 'room_say', AGENT),
    ('GET', rf'/rooms/{ROOM}/wait', 'room_wait', AGENT),
    ('GET', rf'/rooms/{ROOM}/messages', 'room_messages', CONTENT),
    ('POST', rf'/rooms/{ROOM}/heartbeat', 'room_heartbeat', frozenset({'agent', 'monitor'})),
    ('GET', rf'/rooms/{ROOM}/members', 'room_members', METADATA),
    ('GET', rf'/rooms/{ROOM}/monitor', 'room_monitor', METADATA),
    ('GET', rf'/rooms/{ROOM}/stats', 'room_stats', METADATA),
    ('GET', rf'/rooms/{ROOM}/tasks', 'room_tasks', AGENT),
    ('POST', rf'/rooms/{ROOM}/task', 'room_task', AGENT),
    ('POST', rf'/rooms/{ROOM}/done', 'room_done', AGENT),
    ('POST', rf'/rooms/{ROOM}/release', 'room_release', AGENT),
    # room sync: shared state, agreement rounds, status declarations
    ('GET', rf'/rooms/{ROOM}/state', 'sync_state', AGENT),
    ('POST', rf'/rooms/{ROOM}/state/propose', 'sync_propose', AGENT),
    ('POST', rf'/rooms/{ROOM}/state/ack', 'sync_ack', AGENT),
    ('POST', rf'/rooms/{ROOM}/state/nack', 'sync_nack', AGENT),
    ('POST', rf'/rooms/{ROOM}/status', 'sync_status', AGENT),
    ('GET', rf'/rooms/{ROOM}/sync', 'sync_monitor', METADATA),
    # room administration (human)
    ('GET', rf'/admin/rooms/{ROOM}/state', 'admin_sync_state', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/sync/abort', 'admin_sync_abort', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/sync/remove', 'admin_sync_remove', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/sync/reset', 'admin_sync_reset', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/sync/settings', 'admin_sync_settings', ADMIN),
    ('GET', r'/admin/rooms', 'admin_rooms', ADMIN),
    ('POST', r'/admin/rooms', 'admin_create_room', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/close', 'admin_close', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/reopen', 'admin_reopen', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/inject', 'admin_inject', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/reset-thread', 'admin_reset_thread', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/members', 'admin_add_member', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/members/{NAME}/revoke', 'admin_revoke_member', ADMIN),
    ('POST', rf'/admin/rooms/{ROOM}/members/{NAME}/rotate', 'admin_rotate_member', ADMIN),
]]


def _int(q, key, default, lo=0, hi=2**63 - 1):
    raw = q.get(key, [str(default)])[0]
    if not re.fullmatch(r'[0-9]{1,18}', raw) or not lo <= int(raw) <= hi:
        raise DomainError(400, f'invalid {key}')
    return int(raw)


def _recipients(value):
    if value == '*' or (isinstance(value, list) and all(isinstance(v, str) for v in value)):
        return value
    raise DomainError(400, "to must be '*' or a list of names")


def make_handler(hub):
    domain = hub.domain

    class Handler(BaseHTTPRequestHandler):
        timeout = SOCKET_TIMEOUT
        unread = 0
        framing_failed = False

        def log_message(self, *args):
            pass

        def reply(self, code, body, headers=(), ctype='application/json'):
            if isinstance(body, bytes):
                data = body
            else:
                data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('content-type', ctype)
            self.send_header('content-length', str(len(data)))
            given = {key.lower() for key, _ in headers}
            for key, value in (('cache-control', 'no-store'), ('x-content-type-options', 'nosniff')):
                if key not in given:  # the web UI supplies its own security headers; never duplicate
                    self.send_header(key, value)
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def fail(self, code, message, headers=()):
            path = urlparse(self.path).path
            if hub.web is not None and (path == '/ui' or path.startswith('/ui/')):
                headers = [*headers, *hub.web.sec.headers()]  # every /ui error carries the same security headers
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

        def discard_pending(self):
            """Best-effort, bounded read of bytes already in flight after a framing error. Closing a socket that still holds
            unread data makes some stacks (notably Windows) reset the connection and lose the error reply."""
            self.close_connection = True
            deadline = time.monotonic() + DISCARD_SECONDS  # absolute budget: a slow-drip sender cannot hold the worker
            total = 0
            try:
                while total < DRAIN_LIMIT:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        break
                    self.connection.settimeout(left)
                    chunk = self.connection.recv(65536)
                    if not chunk:
                        break
                    total += len(chunk)
            except OSError:
                pass

        def match(self, method, path):
            for m, pattern, handler, roles in ROUTES:
                found = pattern.fullmatch(path) if m == method else None
                if found:
                    return handler, roles, found.groupdict()
            return None

        def handle_request(self, method):
            try:
                self.unread = self.framing()
            except DomainError:
                self.framing_failed = True  # body length is unknowable: reply, then discard what the client already sent
                raise
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if url.path == '/ui' or url.path.startswith('/ui/'):
                if hub.web is None:
                    return self.fail(404, 'not found')
                return hub.web.dispatch(self, method.upper(), url.path, q, _int)
            if 'key' in q or 'token' in q:
                return self.fail(400, 'credentials in the URL are not accepted; use the Authorization header')
            header = self.headers.get('authorization')
            who = authenticate(domain, header)
            if who is None:
                return self.fail(401, 'missing or invalid token', [('www-authenticate', 'Bearer')])
            self.token_hash = hash_token(bearer_token(header))
            delay = hub.take((who.get('room'), who['name']))
            if delay:
                return self.fail(429, 'rate limit exceeded', [('retry-after', str(int(delay) + 1))])
            entry = self.match(method.upper(), url.path)
            if entry is None:
                return self.fail(404, 'not found')
            handler, roles, params = entry
            if who['role'] not in roles:
                return self.fail(403, f"{' or '.join(sorted(roles))} role required")
            room = params.get('room')
            if room is not None and who.get('room') not in (None, room):
                return self.fail(403, 'credential is not valid in this room')
            if room is None and handler.startswith(LEGACY_PREFIXES) and who.get('room') not in (None, DEFAULT_ROOM):
                return self.fail(403, 'legacy routes accept default-room credentials only')
            body = self.body() if method == 'post' else {}
            if 'from' in body and body['from'] != who['name']:
                return self.fail(400, 'from does not match authenticated identity')
            getattr(self, 'do_' + handler)(who, q, body, **params)

        def dispatch(self, method):
            try:
                try:
                    self.handle_request(method)
                finally:
                    self.drain()
            except DomainError as err:
                retry = getattr(err, 'retry_after', 60 if err.code == 429 else None)
                self.fail(err.code, err.message, [('retry-after', str(retry))] if retry else ())
                if self.framing_failed:
                    self.discard_pending()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True
            except Exception as err:
                status = getattr(err, 'status', None)  # web_security.GuardError(status, message)
                if isinstance(status, int) and 400 <= status < 500:
                    self.fail(status, getattr(err, 'message', 'request rejected'))
                else:
                    self.fail(500, 'internal error')

        def do_GET(self):
            self.dispatch('get')

        def do_POST(self):
            self.dispatch('post')

        # ---- helpers ----
        def wait_reply(self, who, q, room, legacy=False):
            """Long poll for `room`. Every poll re-authenticates the bearer token, so revocation,
            rotation and room closure are noticed within one wake-up interval."""
            def fetch(after):
                principal = self.reauth()
                if principal.get('room') not in (None, room):
                    raise DomainError(403, 'credential is not valid in this room')
                if legacy:
                    return domain.fetch(principal, after, 100)  # v1 envelope: scalar `to`
                return domain.room_fetch(principal, room, after, 100)

            def closed():
                return domain.room_state(self.reauth(), room)['status'] == 'closed'

            after = _int(q, 'after', 0)
            timeout = _int(q, 'timeout', MAX_WAIT, 0, MAX_WAIT)
            self.tick(room)
            domain.sync_wait(who, room, True)     # lets stall detection see this open wait; always undone below
            try:
                msgs, cursor, is_closed = hub.wait_for(room, who['name'], fetch, closed, after, timeout)
            finally:
                domain.sync_wait(who, room, False)
            self.tick(room)
            is_closed = is_closed or closed()  # always report the actual room state, even with queued messages
            self.reply(200, {'messages': msgs, 'cursor': cursor, 'timeout': not msgs and not is_closed,
                             'closed': is_closed, 'sync': self.sync_summary(who, room)})

        def tick(self, room):
            """Scan `room` for stalls on entry to say/wait; wake waiters if a notice was recorded."""
            try:
                if domain.sync_scan(room).get('notice'):
                    hub.wake()
            except DomainError:
                pass
            except Exception:
                log.exception('sync scan failed for room %s', room)

        def sync_summary(self, who, room):
            """Safe sync summary for responses (version, round_open, unacked, stalled, strict), or None if unavailable."""
            try:
                return domain.sync_summary(who, room)
            except DomainError:
                return None

        def say_args(self, body):
            if not isinstance(body.get('text'), str):
                raise DomainError(400, 'text required')
            return _recipients(body.get('to')), body.get('thread', 'main'), body['text']

        # ---- legacy routes (room 'default'); legacy waits re-authenticate their bearer token each poll ----
        def reauth(self):
            """Re-run bearer lookup: default-room principals carry no generation to detect revocation."""
            principal = domain.lookup(self.token_hash)
            if principal is None:
                raise DomainError(403, 'credentials revoked')
            return principal

        def do_legacy_wait(self, who, q, body):
            self.wait_reply(who, q, DEFAULT_ROOM, legacy=True)

        def do_legacy_messages(self, who, q, body):
            rows = domain.fetch(who, _int(q, 'after', 0), _int(q, 'limit', 100, 1, 1000))
            self.reply(200, {'messages': rows, 'cursor': rows[-1]['id'] if rows else _int(q, 'after', 0)})

        def do_legacy_tasks(self, who, q, body):
            self.reply(200, {'tasks': domain.tasks()})

        def do_legacy_status(self, who, q, body):
            self.reply(200, domain.status())

        def do_legacy_observe(self, who, q, body):
            rows = domain.fetch(who, 0, 1000)
            text = '\n\n'.join(f"[{m['id']}] {m['from']} -> {m['to']} ({m['thread']}): {m['text']}" for m in rows)
            self.reply(200, text, ctype='text/plain; charset=utf-8')

        def do_legacy_say(self, who, q, body):
            if not isinstance(body.get('text'), str):
                raise DomainError(400, 'text required')
            self.tick(DEFAULT_ROOM)
            try:
                msg = domain.post(who['name'], body.get('to'), body.get('thread', 'main'), body['text'],
                                  state_version=body.get('state_version'))
            except DomainError as err:
                if err.code == 409 and 'state_version' in err.message:
                    return self.reply(409, {'error': err.message, 'code': 409, 'sync': self.sync_summary(who, DEFAULT_ROOM)})
                raise
            hub.wake()
            self.tick(DEFAULT_ROOM)
            self.reply(200, {'id': msg['id'], 'sync': self.sync_summary(who, DEFAULT_ROOM)})

        def do_legacy_task(self, who, q, body):
            self.reply(200, domain.create_task(who['name'], body.get('title'), body.get('files')))

        def do_legacy_done(self, who, q, body):
            self.reply(200, domain.finish_task(who['name'], body.get('id'), body.get('branch')))

        def do_legacy_release(self, who, q, body):
            self.reply(200, domain.release_task(who['name'], body.get('id')))

        def do_admin_pause(self, who, q, body):
            domain.pause()
            self.reply(200, {'paused': True})

        def do_admin_resume(self, who, q, body):
            domain.resume()
            hub.wake()
            self.reply(200, {'paused': False})

        def do_legacy_reset_thread(self, who, q, body):
            domain.reset_thread(body.get('thread'))
            self.reply(200, {'ok': True})

        # ---- room routes ----
        def do_room_say(self, who, q, body, room):
            to, thread, text = self.say_args(body)
            self.tick(room)
            try:
                env = domain.room_post(who, room, to, thread, text, state_version=body.get('state_version'))
            except DomainError as err:
                if err.code == 409 and 'state_version' in err.message:
                    # strict mode: tell the agent which version it must re-sync to
                    return self.reply(409, {'error': err.message, 'code': 409, 'sync': self.sync_summary(who, room)})
                raise
            hub.wake()
            self.tick(room)
            self.reply(200, {'id': env['id'], 'sync': self.sync_summary(who, room)})

        def do_room_wait(self, who, q, body, room):
            self.wait_reply(who, q, room)

        def do_room_messages(self, who, q, body, room):
            after = _int(q, 'after', 0)
            rows = domain.room_fetch(who, room, after, _int(q, 'limit', 100, 1, 1000))
            self.reply(200, {'messages': rows, 'cursor': rows[-1]['id'] if rows else after,
                             'closed': domain.room_state(who, room)['status'] == 'closed'})

        def do_room_heartbeat(self, who, q, body, room):
            self.reply(200, domain.heartbeat(who, room))

        def do_room_members(self, who, q, body, room):
            members = domain.members(who, room)
            for member in members:
                member['waiting'] = hub.waiting(room, member['name'])
            self.reply(200, {'members': members})

        def do_room_monitor(self, who, q, body, room):
            after = _int(q, 'after', 0)
            rows = domain.monitor(who, room, after, _int(q, 'limit', 100, 1, 1000))
            self.reply(200, {'events': rows, 'cursor': rows[-1]['id'] if rows else after})

        def do_room_stats(self, who, q, body, room):
            self.reply(200, domain.stats(who, room))

        def do_room_tasks(self, who, q, body, room):
            self.reply(200, {'tasks': domain.room_tasks(who, room)})

        def do_room_task(self, who, q, body, room):
            self.reply(200, domain.room_task_create(who, room, body.get('title'), body.get('files')))

        def do_room_done(self, who, q, body, room):
            self.reply(200, domain.room_task_finish(who, room, body.get('id'), body.get('branch')))

        def do_room_release(self, who, q, body, room):
            self.reply(200, domain.room_task_release(who, room, body.get('id')))

        # ---- room sync ----
        def do_sync_state(self, who, q, body, room):
            result = domain.sync_state(who, room)
            hub.wake()  # a scan inside sync_state may have recorded a notice
            self.reply(200, result)

        def do_sync_propose(self, who, q, body, room):
            result = domain.sync_propose(who, room, body.get('base_version'), body.get('state'), body.get('phase'),
                                         body.get('enrolled'), body.get('deadline_seconds'))
            hub.wake()
            self.reply(200, result)

        def do_sync_ack(self, who, q, body, room):
            self.reply(200, domain.sync_ack(who, room, body.get('version')))
            hub.wake()

        def do_sync_nack(self, who, q, body, room):
            self.reply(200, domain.sync_nack(who, room, body.get('version'), body.get('reason', '')))
            hub.wake()

        def do_sync_status(self, who, q, body, room):
            result = domain.sync_status(who, room, body.get('state_version'), body.get('waiting_on'),
                                        body.get('reason', ''), body.get('deadline_seconds'))
            hub.wake()
            self.reply(200, result)

        def do_sync_monitor(self, who, q, body, room):
            self.reply(200, domain.sync_monitor(who, room))

        def do_admin_sync_state(self, who, q, body, room):
            self.reply(200, domain.sync_state(who, room))

        def do_admin_sync_abort(self, who, q, body, room):
            self.reply(200, domain.sync_abort(who, room))
            hub.wake()

        def do_admin_sync_remove(self, who, q, body, room):
            self.reply(200, domain.sync_remove(who, room, body.get('name')))
            hub.wake()

        def do_admin_sync_reset(self, who, q, body, room):
            self.reply(200, domain.sync_reset(who, room, body.get('version')))
            hub.wake()

        def do_admin_sync_settings(self, who, q, body, room):
            allowed = {'strict', 'auto_pass', 'stall_seconds', 'turn'}
            unknown = set(body) - allowed
            if unknown:
                raise DomainError(400, 'unknown settings: ' + ', '.join(sorted(unknown)))
            self.reply(200, domain.set_room_sync(who, room, **{k: body[k] for k in allowed if k in body}))  # turn may be null
            hub.wake()

        # ---- room administration ----
        def do_admin_rooms(self, who, q, body):
            self.reply(200, {'rooms': domain.list_rooms(who)})

        def do_admin_create_room(self, who, q, body):
            members = body.get('members', [])
            if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
                raise DomainError(400, 'members must be a list of names')
            self.reply(200, domain.create_room(who, body.get('name'), members))

        def do_admin_close(self, who, q, body, room):
            result = domain.set_room_closed(who, room, True)
            hub.wake()
            self.reply(200, result)

        def do_admin_reopen(self, who, q, body, room):
            self.reply(200, domain.set_room_closed(who, room, False))

        def do_admin_inject(self, who, q, body, room):
            to, thread, text = self.say_args(body)
            env = domain.inject(who, room, to, thread, text)
            hub.wake()
            self.reply(200, {'id': env['id']})

        def do_admin_reset_thread(self, who, q, body, room):
            domain.reset_room_thread(who, room, body.get('thread'))
            self.reply(200, {'ok': True})

        def do_admin_add_member(self, who, q, body, room):
            token = domain.mint_member(who, room, body.get('name'), body.get('role', 'agent'))
            self.reply(200, {'name': body.get('name'), 'token': token})

        def do_admin_revoke_member(self, who, q, body, room, name):
            domain.revoke_member(who, room, name)
            hub.wake()
            self.reply(200, {'ok': True})

        def do_admin_rotate_member(self, who, q, body, room, name):
            token = domain.rotate_member(who, room, name)
            hub.wake()
            self.reply(200, {'name': name, 'token': token})

    return Handler


SYNC_INTERVAL = 5.0


def enabled_sync_rooms(domain):
    """Open rooms that use sync, so the watcher never scans idle rooms."""
    return domain.sync_enabled_rooms()


class Watcher(threading.Thread):
    """Background stall scan for rooms that use sync. sync_scan is idempotent and records its own notices;
    this thread only wakes long-polling waiters when a notice was written."""

    def __init__(self, hub, interval, rooms=None):
        super().__init__(daemon=True, name='sync-watcher')
        self.hub, self.interval, self.stop = hub, interval, threading.Event()
        self.rooms = rooms or (lambda: enabled_sync_rooms(hub.domain))

    def scan_once(self):
        domain = self.hub.domain
        for room in self.rooms():
            try:
                result = domain.sync_scan(room)
            except DomainError:
                continue  # expected: room closed or removed mid-scan
            except Exception:
                log.exception('sync scan failed for room %s', room)  # one bad room must not starve the others
                continue
            if result.get('notice'):
                self.hub.wake()

    def run(self):
        while not self.stop.wait(self.interval):
            try:
                self.scan_once()
            except Exception:  # never let the watcher thread die, but never fail silently either
                log.exception('sync watcher pass failed')


class RelayServer(ThreadingHTTPServer):
    watcher = None

    def stop_watcher(self):
        if self.watcher is not None:
            self.watcher.stop.set()
            if self.watcher.is_alive() and self.watcher is not threading.current_thread():
                self.watcher.join(5)

    def shutdown(self):
        self.stop_watcher()
        super().shutdown()

    def server_close(self):
        self.stop_watcher()
        super().server_close()


LOOPBACK = ('127.0.0.1', 'localhost', '::1')


def make_server(domain, host='127.0.0.1', port=8765, public_origin=None, ui=True, sync_interval=SYNC_INTERVAL):
    """Build the relay server. The web UI is served only when ui is true; its trusted origin is configured,
    never derived from request headers (public_origin is required for non-loopback binds)."""
    hub = Hub(domain)
    server = RelayServer((host, port), make_handler(hub))
    server.daemon_threads = True
    server.hub = hub
    if ui:
        from .web import Web
        from .web_security import WebSecurity
        if public_origin is None:
            if host not in LOOPBACK:
                server.server_close()
                raise ValueError('--public-origin is required to serve the web UI on a non-loopback address')
            public_origin = f'http://{host if host != "::1" else "[::1]"}:{server.server_address[1]}'
        hub.web = Web(hub, WebSecurity(public_origin))
        server.public_origin = public_origin
    if sync_interval:
        server.watcher = Watcher(hub, sync_interval)
        server.watcher.start()
    return server
