"""Atomic relay rules; HTTP authentication/authorization belongs to the server.

Mutating methods take authenticated principal names, never client-supplied names.
Administrative methods must only be exposed to an authenticated admin.
"""
import hashlib
import re
import secrets
import time


class DomainError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def _string(value, field, maximum=128):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DomainError(400, f'invalid {field}')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise DomainError(400, f'{field} must be valid Unicode') from None
    if any(ord(char) < 32 for char in value):
        raise DomainError(400, f'invalid control character in {field}')
    return value


def _integer(value, field, minimum=0, maximum=2**63-1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise DomainError(400, f'invalid {field}')
    return value


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value):
        raise DomainError(400, 'invalid agent name')
    return value


def _path(value):
    value = _string(value, 'file path', 1024).replace('\\', '/')
    if value.startswith('/') or ':' in value or '\x00' in value:
        raise DomainError(400, 'file paths must be relative')
    parts = value.rstrip('/').split('/')
    if any(p in ('', '.', '..') or p.endswith((' ', '.')) for p in parts):
        raise DomainError(400, 'noncanonical file path')
    return '/'.join(parts).casefold()


def _overlap(a, b):
    return a == b or a.startswith(b + '/') or b.startswith(a + '/')


class Domain:
    def __init__(self, store, *, hourly_messages=500, hourly_threads=100, thread_budget=100):
        self.store = store
        self.hourly_messages = _integer(hourly_messages, 'hourly_messages', 1)
        self.hourly_threads = _integer(hourly_threads, 'hourly_threads', 1)
        self.thread_budget = _integer(thread_budget, 'thread_budget', 1)

    @staticmethod
    def _agent(db, name):
        _name(name)
        row = db.execute('SELECT name,role FROM agents WHERE name=? AND active=1',
                         (name,)).fetchone()
        if row is None:
            raise DomainError(403, 'unknown or revoked agent')
        return dict(row)

    @classmethod
    def _writer(cls, db, name):
        agent = cls._agent(db, name)
        if agent['role'] != 'agent':
            raise DomainError(403, 'agent role required')
        paused = db.execute("SELECT value FROM settings WHERE key='paused'").fetchone()[0]
        if paused == '1':
            raise DomainError(423, 'relay paused by administrator')
        return agent

    def mint_agent(self, name, role='agent'):
        _name(name)
        if role not in ('agent', 'observer', 'admin'):
            raise DomainError(400, 'invalid role')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.store.transaction() as db:
            if db.execute('SELECT 1 FROM agents WHERE name=?', (name,)).fetchone():
                raise DomainError(409, 'name already exists; identities cannot be reused')
            db.execute('INSERT INTO agents(name,role,token_hash) VALUES (?,?,?)',
                       (name, role, digest))
        return token

    def lookup(self, token_hash):
        if not isinstance(token_hash, str) or len(token_hash) != 64:
            return None
        with self.store.transaction(read_only=True) as db:
            row = db.execute('SELECT name,role FROM agents WHERE token_hash=? AND active=1',
                             (token_hash,)).fetchone()
            return dict(row) if row else None

    def revoke(self, name):
        with self.store.transaction() as db:
            agent = self._agent(db, name)
            if agent['role'] == 'admin' and db.execute(
                    "SELECT count(*) FROM agents WHERE role='admin' AND active=1").fetchone()[0] <= 1:
                raise DomainError(409, 'cannot revoke the last active administrator')
            db.execute('UPDATE agents SET active=0 WHERE name=?', (name,))

    @staticmethod
    def _message(row):
        return {'id': row['id'], 'from': row['sender'], 'to': row['recipient'],
                'thread': row['thread'], 'text': row['text'],
                'untrusted': True, 'ts': row['created']}

    def post(self, sender, to, thread, text):
        _name(sender)
        _name(to)
        _string(thread, 'thread', 128)
        if not isinstance(text, str) or not text.strip():
            raise DomainError(400, 'invalid text')
        try:
            size = len(text.encode('utf-8'))
        except UnicodeEncodeError:
            raise DomainError(400, 'text must be valid Unicode') from None
        if size > 8192:
            raise DomainError(413, 'text exceeds 8192 UTF-8 bytes')
        now = time.time()
        with self.store.transaction() as db:
            self._writer(db, sender)
            recipient = self._agent(db, to)
            if to == sender or recipient['role'] != 'agent':
                raise DomainError(400, 'recipient must be another active agent')
            count = db.execute('SELECT count(*) FROM messages WHERE sender=? AND created>?',
                               (sender, now - 3600)).fetchone()[0]
            if count >= self.hourly_messages:
                raise DomainError(429, 'hourly message budget exhausted')
            pair = sorted((sender, to))
            existing = db.execute('SELECT * FROM threads WHERE id=?', (thread,)).fetchone()
            if existing is not None:
                if pair != [existing['participant_a'], existing['participant_b']]:
                    raise DomainError(409, 'thread belongs to different participants')
                if existing['used'] >= self.thread_budget:
                    raise DomainError(409, 'thread budget exhausted; admin reset required')
            else:
                count = db.execute('SELECT count(*) FROM threads WHERE creator=? AND created>?',
                                   (sender, now - 3600)).fetchone()[0]
                if count >= self.hourly_threads:
                    raise DomainError(429, 'hourly thread creation budget exhausted')
                db.execute('INSERT INTO threads(id,participant_a,participant_b,creator,created) '
                           'VALUES (?,?,?,?,?)', (thread, *pair, sender, now))
            cursor = db.execute('INSERT INTO messages(sender,recipient,thread,text,created) '
                                'VALUES (?,?,?,?,?)', (sender, to, thread, text, now))
            db.execute('UPDATE threads SET used=used+1 WHERE id=?', (thread,))
            row = db.execute('SELECT * FROM messages WHERE id=?', (cursor.lastrowid,)).fetchone()
            return self._message(row)

    def fetch(self, agent, after=0, limit=100):
        _integer(after, 'after')
        _integer(limit, 'limit', 1, 1000)
        if not isinstance(agent, dict) or not {'name', 'role'} <= set(agent):
            raise DomainError(403, 'invalid principal')
        with self.store.transaction(read_only=True) as db:
            actual = self._agent(db, agent.get('name'))
            if actual['role'] != agent.get('role'):
                raise DomainError(403, 'invalid principal role')
            if actual['role'] == 'agent':
                rows = db.execute('SELECT * FROM messages WHERE id>? AND '
                                  '(sender=? OR recipient=?) ORDER BY id LIMIT ?',
                                  (after, actual['name'], actual['name'], limit)).fetchall()
            else:
                rows = db.execute('SELECT * FROM messages WHERE id>? ORDER BY id LIMIT ?',
                                  (after, limit)).fetchall()
            return [self._message(row) for row in rows]

    @staticmethod
    def _task(db, row):
        task = dict(row)
        task['files'] = [r[0] for r in db.execute('SELECT COALESCE(display_path,path) FROM claims WHERE task_id=? ORDER BY path',
                                                (row['id'],))]
        return task

    def create_task(self, owner, title, files):
        _string(title, 'title', 256)
        if not isinstance(files, list) or not 1 <= len(files) <= 100:
            raise DomainError(400, 'files must contain 1 to 100 relative paths')
        paths = [_path(p) for p in files]
        for i, path in enumerate(paths):
            if any(_overlap(path, other) for other in paths[:i]):
                raise DomainError(409, 'overlapping paths in task')
        with self.store.transaction() as db:
            self._writer(db, owner)
            for row in db.execute('SELECT task_id,path FROM claims'):
                if any(_overlap(p, row['path']) for p in paths):
                    raise DomainError(409, f"file overlaps task {row['task_id']}")
            cur = db.execute('INSERT INTO tasks(owner,title) VALUES (?,?)', (owner, title))
            db.executemany('INSERT INTO claims(task_id,path,display_path) VALUES (?,?,?)',
                           [(cur.lastrowid, key, original.replace('\\', '/').rstrip('/'))
                            for key, original in zip(paths, files)])
            return self._task(db, db.execute('SELECT * FROM tasks WHERE id=?',
                                            (cur.lastrowid,)).fetchone())

    def _owned(self, db, owner, task_id):
        self._writer(db, owner)
        _integer(task_id, 'task id', 1)
        row = db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        if row is None:
            raise DomainError(404, 'no such task')
        if row['owner'] != owner:
            raise DomainError(403, 'task belongs to another agent')
        if row['status'] == 'released':
            raise DomainError(409, 'task already released')
        return row

    def finish_task(self, owner, id, branch):
        _name(owner)
        _string(branch, 'branch', 256)
        if not branch.startswith(owner + '/') or not re.fullmatch(r'[A-Za-z0-9_./-]+', branch):
            raise DomainError(400, 'branch must belong to task owner')
        if '..' in branch or any(not p or p.startswith('.') or p.endswith(('.', '.lock'))
                                 for p in branch.split('/')):
            raise DomainError(400, 'invalid branch')
        with self.store.transaction() as db:
            task = self._owned(db, owner, id)
            if task['status'] != 'open':
                raise DomainError(409, 'only open tasks can be finished')
            db.execute("UPDATE tasks SET status='done',branch=? WHERE id=?", (branch, id))
            return self._task(db, db.execute('SELECT * FROM tasks WHERE id=?', (id,)).fetchone())

    def release_task(self, owner, id):
        with self.store.transaction() as db:
            self._owned(db, owner, id)
            db.execute('DELETE FROM claims WHERE task_id=?', (id,))
            db.execute("UPDATE tasks SET status='released' WHERE id=?", (id,))
            return self._task(db, db.execute('SELECT * FROM tasks WHERE id=?', (id,)).fetchone())

    def tasks(self):
        with self.store.transaction(read_only=True) as db:
            return [self._task(db, row) for row in db.execute('SELECT * FROM tasks ORDER BY id')]

    def status(self):
        with self.store.transaction(read_only=True) as db:
            owners = {}
            for task in db.execute('SELECT * FROM tasks'):
                owner = owners.setdefault(task['owner'], {'tasks': 0, 'done': 0, 'files': 0})
                owner['tasks'] += 1
                owner['done'] += task['status'] == 'done'
                owner['files'] += db.execute('SELECT count(*) FROM claims WHERE task_id=?',
                                             (task['id'],)).fetchone()[0]
            total = sum(o['files'] for o in owners.values()) or 1
            for owner in owners.values():
                owner['file_share'] = round(owner['files'] / total, 2)
            return {'owners': owners, 'messages': db.execute('SELECT count(*) FROM messages').fetchone()[0],
                    'paused': db.execute("SELECT value FROM settings WHERE key='paused'").fetchone()[0] == '1'}

    def pause(self):
        self._set_paused(True)

    def resume(self):
        self._set_paused(False)

    def _set_paused(self, paused):
        with self.store.transaction() as db:
            db.execute("UPDATE settings SET value=? WHERE key='paused'", ('1' if paused else '0',))

    def is_paused(self):
        with self.store.transaction(read_only=True) as db:
            return db.execute("SELECT value FROM settings WHERE key='paused'").fetchone()[0] == '1'

    def reset_thread(self, thread):
        _string(thread, 'thread', 128)
        with self.store.transaction() as db:
            if not db.execute('SELECT 1 FROM threads WHERE id=?', (thread,)).fetchone():
                raise DomainError(404, 'no such thread')
            db.execute('UPDATE threads SET used=0 WHERE id=?', (thread,))
