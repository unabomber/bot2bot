"""Atomic relay rules; HTTP authentication/authorization belongs to the server.

Mutating methods take authenticated principal names, never client-supplied names.
Administrative methods must only be exposed to an authenticated admin.
"""
import hashlib
import json
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
    def __init__(self, store, *, hourly_messages=500, hourly_threads=100, thread_budget=100, hourly_injections=60):
        self.store = store
        self.hourly_messages = _integer(hourly_messages, 'hourly_messages', 1)
        self.hourly_threads = _integer(hourly_threads, 'hourly_threads', 1)
        self.thread_budget = _integer(thread_budget, 'thread_budget', 1)
        self.hourly_injections = _integer(hourly_injections, 'hourly_injections', 1)

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
        if db.execute("SELECT status FROM rooms WHERE id='default'").fetchone()[0] == 'closed':
            raise DomainError(423, 'room closed')
        return agent

    def mint_agent(self, name, role='agent'):
        _name(name)
        if (name.casefold() == 'human' and role != 'admin') or role not in ('agent', 'observer', 'admin'):
            raise DomainError(400, 'invalid role')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.store.transaction() as db:
            if db.execute('SELECT 1 FROM agents WHERE name=?', (name,)).fetchone():
                raise DomainError(409, 'name already exists; identities cannot be reused')
            db.execute('INSERT INTO agents(name,role,token_hash) VALUES (?,?,?)',
                       (name, role, digest))
            if role != 'admin':
                if db.execute("SELECT 1 FROM room_members WHERE room_id='default' AND name=?", (name,)).fetchone():
                    raise DomainError(409, 'member identity already exists')
                db.execute("INSERT INTO room_members(room_id,name,role,token_hash) VALUES ('default',?,?,?)", (name,role,digest))
        return token

    def lookup(self, token_hash):
        if not isinstance(token_hash, str) or len(token_hash) != 64:
            return None
        with self.store.transaction(read_only=True) as db:
            row = db.execute('SELECT name,role FROM agents WHERE token_hash=? AND active=1',
                             (token_hash,)).fetchone()
            member = db.execute('SELECT room_id,name,role,generation,last_seen FROM room_members WHERE token_hash=? AND active=1', (token_hash,)).fetchone()
            if row is None and member is None:
                return None
            result = dict(row) if row else {'name':member['name'],'role':member['role'],'room':member['room_id'],'generation':member['generation']}
            now = time.time()
            touch = member is not None and (member['last_seen'] is None or member['last_seen'] <= now-10)
        if touch:
            with self.store.transaction() as db:
                db.execute('UPDATE room_members SET last_seen=? WHERE token_hash=? AND active=1 AND (last_seen IS NULL OR last_seen<=?)', (now,token_hash,now-10))
        return result

    def revoke(self, name):
        with self.store.transaction() as db:
            agent = self._agent(db, name)
            if agent['role'] == 'admin' and db.execute(
                    "SELECT count(*) FROM agents WHERE role='admin' AND active=1").fetchone()[0] <= 1:
                raise DomainError(409, 'cannot revoke the last active administrator')
            db.execute('UPDATE agents SET active=0 WHERE name=?', (name,))
            db.execute("UPDATE room_members SET active=0,generation=generation+1 WHERE room_id='default' AND name=?", (name,))

    @staticmethod
    def _message(row):
        to = json.loads(row['recipient']) if row['recipient'].startswith('[') else [row['recipient']]
        return {'id': row['id'], 'from': row['sender'], 'to': to[0] if len(to)==1 else to,
                'thread': row['label'] if 'label' in row.keys() else row['thread'], 'text': row['text'],
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
            count = db.execute("SELECT count(*) FROM messages WHERE room_id='default' AND source='agent' AND sender=? AND created>?",
                               (sender, now - 3600)).fetchone()[0]
            if count >= self.hourly_messages:
                raise DomainError(429, 'hourly message budget exhausted')
            pair = sorted((sender, to))
            room_thread = db.execute("SELECT * FROM room_threads WHERE room_id='default' AND label=?", (thread,)).fetchone()
            if room_thread is not None and room_thread['used'] >= self.thread_budget:
                raise DomainError(409, 'thread budget exhausted; admin reset required')
            existing = db.execute("SELECT * FROM threads WHERE id=? AND room_id='default'", (thread,)).fetchone()
            if existing is not None:
                if pair != [existing['participant_a'], existing['participant_b']]:
                    raise DomainError(409, 'thread belongs to different participants')
                if room_thread is None and existing['used'] >= self.thread_budget:
                    raise DomainError(409, 'thread budget exhausted; admin reset required')
            else:
                count = db.execute("SELECT count(*) FROM room_threads WHERE room_id='default' AND creator=? AND created>?",
                                   (sender, now - 3600)).fetchone()[0]
                if room_thread is None and count >= self.hourly_threads:
                    raise DomainError(429, 'hourly thread creation budget exhausted')
                if db.execute("SELECT 1 FROM threads WHERE id=? AND room_id!='default'", (thread,)).fetchone():
                    raise DomainError(409, 'legacy thread identifier unavailable')
                db.execute('INSERT INTO threads(id,participant_a,participant_b,creator,created) '
                           'VALUES (?,?,?,?,?)', (thread, *pair, sender, now))
            cursor = db.execute('INSERT INTO messages(sender,recipient,thread,text,created) '
                                'VALUES (?,?,?,?,?)', (sender, to, thread, text, now))
            db.execute('UPDATE threads SET used=used+1 WHERE id=?', (thread,))
            if room_thread is None:
                db.execute("INSERT INTO room_threads(room_id,label,storage_key,creator,created) VALUES ('default',?,?,?,?)", (thread,thread,sender,now))
                room_thread = db.execute("SELECT * FROM room_threads WHERE room_id='default' AND label=?", (thread,)).fetchone()
            db.execute('UPDATE room_threads SET used=used+1 WHERE number=?', (room_thread['number'],))
            db.execute('UPDATE messages SET bytes=?,thread_no=? WHERE id=?', (size,room_thread['number'],cursor.lastrowid))
            db.executemany("INSERT INTO deliveries(room_id,message_id,member) VALUES ('default',?,?)", [(cursor.lastrowid,sender),(cursor.lastrowid,to)])
            row = db.execute('SELECT * FROM messages WHERE id=?', (cursor.lastrowid,)).fetchone()
            return self._message(row)

    def fetch(self, agent, after=0, limit=100):
        _integer(after, 'after')
        _integer(limit, 'limit', 1, 1000)
        if not isinstance(agent, dict) or not {'name', 'role'} <= set(agent) or agent.get('room') not in (None,'default'):
            raise DomainError(403, 'invalid principal')
        with self.store.transaction(read_only=True) as db:
            actual = self._agent(db, agent.get('name'))
            if actual['role'] != agent.get('role'):
                raise DomainError(403, 'invalid principal role')
            if actual['role'] == 'agent':
                rows = db.execute("SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id='default' AND m.id>? AND "
                                  "EXISTS(SELECT 1 FROM deliveries d WHERE d.room_id='default' AND d.message_id=m.id AND d.member=?) ORDER BY m.id LIMIT ?",
                                  (after, actual['name'], limit)).fetchall()
            else:
                rows = db.execute("SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id='default' AND m.id>? ORDER BY m.id LIMIT ?",
                                  (after, limit)).fetchall()
            return [self._message(row) for row in rows]

    @staticmethod
    def _task(db, row):
        task = dict(row)
        task['files'] = [r[0] for r in db.execute('SELECT COALESCE(display_path,path) FROM claims WHERE task_id=? AND room_id=? ORDER BY path',
                                                (row['id'],row['room_id']))]
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
            for row in db.execute("SELECT task_id,path FROM claims WHERE room_id='default'"):
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
        row = db.execute("SELECT * FROM tasks WHERE room_id='default' AND id=?", (task_id,)).fetchone()
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
            return [self._task(db, row) for row in db.execute("SELECT * FROM tasks WHERE room_id='default' ORDER BY id")]

    def status(self):
        with self.store.transaction(read_only=True) as db:
            owners = {}
            for task in db.execute("SELECT * FROM tasks WHERE room_id='default'"):
                owner = owners.setdefault(task['owner'], {'tasks': 0, 'done': 0, 'files': 0})
                owner['tasks'] += 1
                owner['done'] += task['status'] == 'done'
                owner['files'] += db.execute("SELECT count(*) FROM claims WHERE room_id='default' AND task_id=?",
                                             (task['id'],)).fetchone()[0]
            total = sum(o['files'] for o in owners.values()) or 1
            for owner in owners.values():
                owner['file_share'] = round(owner['files'] / total, 2)
            return {'owners': owners, 'messages': db.execute("SELECT count(*) FROM messages WHERE room_id='default'").fetchone()[0],
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
            if not db.execute("SELECT 1 FROM room_threads WHERE room_id='default' AND label=?", (thread,)).fetchone():
                raise DomainError(404, 'no such thread')
            db.execute("UPDATE threads SET used=0 WHERE room_id='default' AND id=?", (thread,))
            db.execute("UPDATE room_threads SET used=0 WHERE room_id='default' AND label=?", (thread,))

    @classmethod
    def _admin(cls, db, p):
        if not isinstance(p,dict) or p.get('room') is not None:
            raise DomainError(403,'global administrator required')
        actual = cls._agent(db,p.get('name'))
        if actual['role'] != 'admin' or p.get('role') != 'admin':
            raise DomainError(403,'global administrator required')
        return actual

    @classmethod
    def _room_auth(cls, db, p, room, capability='read'):
        _name(room)
        if not isinstance(p,dict):
            raise DomainError(403,'invalid principal')
        if p.get('room') is None:
            actual = cls._agent(db,p.get('name'))
            if actual['role'] != p.get('role') or (actual['role'] != 'admin' and room != 'default'):
                raise DomainError(403,'credential scope or role mismatch')
        else:
            if p.get('room') != room:
                raise DomainError(403,'credential belongs to another room')
            row = db.execute('SELECT name,role,generation FROM room_members WHERE room_id=? AND name=? AND active=1',(room,p.get('name'))).fetchone()
            if row is None or row['role'] != p.get('role') or type(p.get('generation')) is not int or row['generation'] != p['generation']:
                raise DomainError(403,'revoked or stale room credential')
            actual = dict(row)
        state = db.execute('SELECT status FROM rooms WHERE id=?',(room,)).fetchone()
        if state is None:
            raise DomainError(404,'no such room')
        allowed = {'read':('agent','observer','monitor','admin'),
                   'content':('agent','observer','admin'),
                   'metadata':('monitor','admin'),'write':('agent',)}[capability]
        if actual['role'] not in allowed:
            raise DomainError(403,'capability not allowed')
        if capability == 'write' and (state['status'] == 'closed' or db.execute("SELECT value FROM settings WHERE key='paused'").fetchone()[0] == '1'):
            raise DomainError(423,'relay paused or room closed')
        return actual

    @staticmethod
    def _event(db, room, actor, action, subject=''):
        db.execute('INSERT INTO room_events(room_id,actor,action,subject,created) VALUES (?,?,?,?,?)',(room,actor,action,subject,time.time()))

    def _mint_member(self, db, room, name, role):
        _name(name)
        if name.casefold() == 'human' or role not in ('agent','monitor'):
            raise DomainError(400,'invalid room member name or role')
        if db.execute('SELECT 1 FROM room_members WHERE room_id=? AND name=?',(room,name)).fetchone() or (room == 'default' and db.execute('SELECT 1 FROM agents WHERE name=?',(name,)).fetchone()):
            raise DomainError(409,'member identity already exists')
        if db.execute('SELECT count(*) FROM room_members WHERE room_id=?',(room,)).fetchone()[0] >= 1000:
            raise DomainError(409,'room member limit reached')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        db.execute('INSERT INTO room_members(room_id,name,role,token_hash) VALUES (?,?,?,?)',(room,name,role,digest))
        if room == 'default' and role == 'agent':
            db.execute('INSERT INTO agents(name,role,token_hash) VALUES (?,?,?)',(name,role,digest))
        return token

    def create_room(self, admin, name, members=None):
        _name(name)
        if name.casefold() in ('default','human'):
            raise DomainError(400,'reserved room name')
        members = [] if members is None else members
        if not isinstance(members,list) or len(members)>100:
            raise DomainError(400,'members must be a list of at most 100 names or objects')
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            if db.execute('SELECT 1 FROM rooms WHERE id=?',(name,)).fetchone():
                raise DomainError(409,'room already exists')
            db.execute('INSERT INTO rooms(id,name,created,creator) VALUES (?,?,?,?)',(name,name,time.time(),actor['name']))
            minted = []
            for member in members:
                if isinstance(member,str):
                    member = {'name':member,'role':'agent'}
                if not isinstance(member,dict):
                    raise DomainError(400,'invalid member')
                token = self._mint_member(db,name,member.get('name'),member.get('role','agent'))
                minted.append({'name':member['name'],'role':member.get('role','agent'),'token':token})
            self._event(db,name,actor['name'],'create')
            return {'room':name,'members':minted}

    def list_rooms(self, admin):
        with self.store.transaction(read_only=True) as db:
            self._admin(db,admin)
            return [dict(r) for r in db.execute('SELECT r.*, '
                '(SELECT count(*) FROM room_members m WHERE m.room_id=r.id AND m.active=1) AS members, '
                '(SELECT count(*) FROM room_members m WHERE m.room_id=r.id AND m.active=1 AND m.last_seen>?) AS active, '
                '(SELECT max(created) FROM messages m WHERE m.room_id=r.id) AS last_activity FROM rooms r ORDER BY r.id',(time.time()-60,))]

    def room_state(self, p, room):
        with self.store.transaction(read_only=True) as db:
            self._room_auth(db,p,room)
            return {'status':db.execute('SELECT status FROM rooms WHERE id=?',(room,)).fetchone()[0]}

    def set_room_closed(self, admin, room, closed):
        if type(closed) is not bool:
            raise DomainError(400,'closed must be boolean')
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            status = 'closed' if closed else 'open'
            db.execute('UPDATE rooms SET status=? WHERE id=?',(status,room))
            self._event(db,room,actor['name'],status)
            return {'room':room,'status':status}

    def mint_member(self, admin, room, name, role='agent'):
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            token = self._mint_member(db,room,name,role)
            self._event(db,room,actor['name'],'mint',name)
            return token

    def revoke_member(self, admin, room, name):
        _name(name)
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            if not db.execute('SELECT 1 FROM room_members WHERE room_id=? AND name=? AND active=1',(room,name)).fetchone():
                raise DomainError(404,'no such active member')
            db.execute('UPDATE room_members SET active=0,generation=generation+1 WHERE room_id=? AND name=?',(room,name))
            if room == 'default':
                db.execute("UPDATE agents SET active=0 WHERE name=? AND role!='admin'",(name,))
            self._event(db,room,actor['name'],'revoke',name)

    def rotate_member(self, admin, room, name):
        _name(name)
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            if not db.execute('SELECT 1 FROM room_members WHERE room_id=? AND name=? AND active=1',(room,name)).fetchone():
                raise DomainError(404,'no such active member')
            db.execute('UPDATE room_members SET token_hash=?,generation=generation+1 WHERE room_id=? AND name=?',(digest,room,name))
            if room == 'default':
                db.execute("UPDATE agents SET token_hash=? WHERE name=? AND role!='admin'",(digest,name))
            self._event(db,room,actor['name'],'rotate',name)
        return token

    @staticmethod
    def _recipients(db, room, to, sender):
        if to == '*':
            names = [r[0] for r in db.execute("SELECT name FROM room_members WHERE room_id=? AND active=1 AND role='agent' AND name!=? ORDER BY name",(room,sender))]
        elif isinstance(to,list) and 1 <= len(to) <= 1000:
            names = sorted({_name(n) for n in to})
        else:
            raise DomainError(400,'to must be a recipient list or *')
        if not names or sender in names:
            raise DomainError(400,'recipient list is empty or includes sender')
        for name in names:
            if not db.execute("SELECT 1 FROM room_members WHERE room_id=? AND name=? AND active=1 AND role='agent'",(room,name)).fetchone():
                raise DomainError(400,'recipient must be an active agent in this room')
        return names

    @staticmethod
    def _envelope(row):
        to = json.loads(row['recipient']) if row['recipient'].startswith('[') else [row['recipient']]
        return {'id':row['id'],'room':row['room_id'],'thread':row['label'],
                'from':row['sender'],'to':to,'ts':row['created'],'source':row['source'],
                'untrusted':True,'text':row['text']}

    def _room_send(self, p, room, to, thread, text, human=False):
        _string(thread,'thread',128)
        if not isinstance(text,str) or not text.strip():
            raise DomainError(400,'invalid text')
        try:
            size = len(text.encode('utf-8'))
        except UnicodeEncodeError:
            raise DomainError(400,'text must be valid Unicode') from None
        if size>8192:
            raise DomainError(413,'text exceeds 8192 UTF-8 bytes')
        now = time.time()
        with self.store.transaction() as db:
            actor = self._admin(db,p) if human else self._room_auth(db,p,room,'write')
            if human:
                self._room_auth(db,p,room)
            sender = 'human' if human else actor['name']
            recipients = self._recipients(db,room,to,sender)
            if human:
                count = db.execute("SELECT count(*) FROM messages WHERE source='human' AND created>?",(now-3600,)).fetchone()[0]
                if count>=self.hourly_injections:
                    raise DomainError(429,'hourly human injection budget exhausted')
            else:
                count = db.execute("SELECT count(*) FROM messages WHERE room_id=? AND sender=? AND source='agent' AND created>?",(room,sender,now-3600)).fetchone()[0]
                if count>=self.hourly_messages:
                    raise DomainError(429,'hourly message budget exhausted')
            t = db.execute('SELECT * FROM room_threads WHERE room_id=? AND label=?',(room,thread)).fetchone()
            if t is None:
                count = db.execute('SELECT count(*) FROM room_threads WHERE room_id=? AND creator=? AND created>?',(room,sender,now-3600)).fetchone()[0]
                if not human and count>=self.hourly_threads:
                    raise DomainError(429,'hourly thread creation budget exhausted')
                key = 'room-'+secrets.token_hex(24)
                db.execute('INSERT INTO threads(id,participant_a,participant_b,creator,created,room_id) VALUES (?,?,?,?,?,?)',(key,sender,recipients[0],sender,now,room))
                db.execute('INSERT INTO room_threads(room_id,label,storage_key,creator,created) VALUES (?,?,?,?,?)',(room,thread,key,sender,now))
                t = db.execute('SELECT * FROM room_threads WHERE room_id=? AND label=?',(room,thread)).fetchone()
            if not human and t['used']>=self.thread_budget:
                raise DomainError(409,'thread budget exhausted; admin reset required')
            cur = db.execute('INSERT INTO messages(sender,recipient,thread,text,created,room_id,source,bytes,thread_no) VALUES (?,?,?,?,?,?,?,?,?)',
                (sender,json.dumps(recipients),t['storage_key'],text,now,room,'human' if human else 'agent',size,t['number']))
            db.executemany('INSERT INTO deliveries(room_id,message_id,member) VALUES (?,?,?)',[(room,cur.lastrowid,n) for n in set(recipients+[sender])])
            if not human:
                db.execute('UPDATE room_threads SET used=used+1 WHERE number=?',(t['number'],))
            else:
                self._event(db,room,actor['name'],'inject',str(cur.lastrowid))
            row = db.execute('SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id=? AND m.id=?',(room,cur.lastrowid)).fetchone()
            return self._envelope(row)

    def room_post(self, p, room, to, thread, text):
        return self._room_send(p,room,to,thread,text)

    def inject(self, admin, room, to, thread, text):
        return self._room_send(admin,room,to,thread,text,human=True)

    def room_fetch(self, p, room, after=0, limit=100):
        _integer(after,'after')
        _integer(limit,'limit',1,1000)
        with self.store.transaction(read_only=True) as db:
            actor = self._room_auth(db,p,room,'content')
            sql = 'SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id=? AND m.id>? '
            args = [room,after]
            if actor['role']=='agent':
                sql += 'AND EXISTS(SELECT 1 FROM deliveries d WHERE d.room_id=m.room_id AND d.message_id=m.id AND d.member=?) '
                args.append(actor['name'])
            return [self._envelope(r) for r in db.execute(sql+'ORDER BY m.id LIMIT ?',(*args,limit))]

    def monitor(self, p, room, after=0, limit=100):
        _integer(after,'after')
        _integer(limit,'limit',1,1000)
        with self.store.transaction(read_only=True) as db:
            self._room_auth(db,p,room,'metadata')
            return [dict(r) for r in db.execute('SELECT m.id,m.created AS ts,m.sender AS "from",m.room_id AS room,m.bytes,m.source,m.thread_no, '
                '(SELECT count(*) FROM deliveries d WHERE d.room_id=m.room_id AND d.message_id=m.id AND d.member!=m.sender) AS to_count '
                'FROM messages m WHERE m.room_id=? AND m.id>? ORDER BY m.id LIMIT ?',(room,after,limit))]

    def stats(self, p, room):
        with self.store.transaction(read_only=True) as db:
            self._room_auth(db,p,room,'metadata')
            senders = [dict(r) for r in db.execute('SELECT sender AS "from",count(*) AS messages,coalesce(sum(bytes),0) AS bytes,max(created) AS last_message FROM messages WHERE room_id=? GROUP BY sender ORDER BY sender',(room,))]
            return {'room':room,'messages':sum(r['messages'] for r in senders),'bytes':sum(r['bytes'] for r in senders),'senders':senders}

    def members(self, p, room):
        with self.store.transaction(read_only=True) as db:
            self._room_auth(db,p,room,'metadata')
            return [{'name':r['name'],'role':r['role'],'last_seen':r['last_seen'],
                     'active':r['last_seen'] is not None and r['last_seen']>time.time()-60}
                    for r in db.execute('SELECT name,role,last_seen FROM room_members WHERE room_id=? AND active=1 ORDER BY name',(room,))]

    def heartbeat(self, p, room):
        with self.store.transaction() as db:
            actor = self._room_auth(db,p,room)
            now = time.time()
            db.execute('UPDATE room_members SET last_seen=? WHERE room_id=? AND name=? AND active=1',(now,room,actor['name']))
            return {'room':room,'name':actor['name'],'last_seen':now,'active':True}

    def room_task_create(self, p, room, title, files):
        _string(title,'title',256)
        if not isinstance(files,list) or not 1<=len(files)<=100:
            raise DomainError(400,'files must contain 1 to 100 relative paths')
        paths = [_path(f) for f in files]
        for i,path in enumerate(paths):
            if any(_overlap(path,other) for other in paths[:i]):
                raise DomainError(409,'overlapping paths in task')
        with self.store.transaction() as db:
            actor = self._room_auth(db,p,room,'write')
            for row in db.execute('SELECT task_id,path FROM claims WHERE room_id=?',(room,)):
                if any(_overlap(path,row['path']) for path in paths):
                    raise DomainError(409,'file overlaps existing task')
            cur = db.execute('INSERT INTO tasks(owner,title,room_id) VALUES (?,?,?)',(actor['name'],title,room))
            db.executemany('INSERT INTO claims(task_id,path,display_path,room_id) VALUES (?,?,?,?)',[(cur.lastrowid,key,raw.replace('\\','/').rstrip('/'),room) for key,raw in zip(paths,files)])
            return self._task(db,db.execute('SELECT * FROM tasks WHERE room_id=? AND id=?',(room,cur.lastrowid)).fetchone())

    def _room_owned(self, db, p, room, id):
        actor = self._room_auth(db,p,room,'write')
        _integer(id,'task id',1)
        row = db.execute('SELECT * FROM tasks WHERE room_id=? AND id=?',(room,id)).fetchone()
        if row is None:
            raise DomainError(404,'no such task')
        if row['owner']!=actor['name']:
            raise DomainError(403,'task belongs to another agent')
        if row['status']=='released':
            raise DomainError(409,'task already released')
        return row

    def room_task_finish(self, p, room, id, branch):
        _string(branch,'branch',256)
        owner = p.get('name') if isinstance(p,dict) else None
        _name(owner)
        if not branch.startswith(owner+'/') or not re.fullmatch(r'[A-Za-z0-9_./-]+',branch) or '..' in branch or any(not part or part.startswith('.') or part.endswith(('.','.lock')) for part in branch.split('/')):
            raise DomainError(400,'invalid owner branch')
        with self.store.transaction() as db:
            row = self._room_owned(db,p,room,id)
            if row['status']!='open':
                raise DomainError(409,'only open tasks can be finished')
            db.execute("UPDATE tasks SET status='done',branch=? WHERE room_id=? AND id=?",(branch,room,id))
            return self._task(db,db.execute('SELECT * FROM tasks WHERE room_id=? AND id=?',(room,id)).fetchone())

    def room_task_release(self, p, room, id):
        with self.store.transaction() as db:
            self._room_owned(db,p,room,id)
            db.execute('DELETE FROM claims WHERE room_id=? AND task_id=?',(room,id))
            db.execute("UPDATE tasks SET status='released' WHERE room_id=? AND id=?",(room,id))
            return self._task(db,db.execute('SELECT * FROM tasks WHERE room_id=? AND id=?',(room,id)).fetchone())

    def room_tasks(self, p, room):
        with self.store.transaction(read_only=True) as db:
            self._room_auth(db,p,room,'content')
            return [self._task(db,r) for r in db.execute('SELECT * FROM tasks WHERE room_id=? ORDER BY id',(room,))]

    def reset_room_thread(self, admin, room, thread):
        _string(thread,'thread',128)
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            cur = db.execute('UPDATE room_threads SET used=0 WHERE room_id=? AND label=?',(room,thread))
            if not cur.rowcount:
                raise DomainError(404,'no such thread')
            if room=='default':
                db.execute('UPDATE threads SET used=0 WHERE id IN (SELECT storage_key FROM room_threads WHERE room_id=? AND label=?)',(room,thread))
            self._event(db,room,actor['name'],'reset-thread')
