"""Atomic relay rules; HTTP authentication/authorization belongs to the server.

Mutating methods take authenticated principal names, never client-supplied names.
Administrative methods must only be exposed to an authenticated admin.
"""
import hashlib
import json
import hmac
import math
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
        self._sync_waits = {}

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
        if name.casefold() == 'relay' or (name.casefold() == 'human' and role != 'admin') or role not in ('agent', 'observer', 'admin'):
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
        return {'id': row['public_id'], 'from': row['sender'], 'to': to[0] if len(to)==1 else to,
                'thread': row['label'] if 'label' in row.keys() else row['thread'], 'text': row['text'],
                'untrusted': True, 'ts': row['created'],
                'source':row['source'] if 'source' in row.keys() else 'agent'}

    def post(self, sender, to, thread, text, state_version=None):
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
            self._sync_check_write(db,'default',state_version)
            if thread == '__relay_sync__':
                raise DomainError(400,'reserved system thread')
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
                number = db.execute("SELECT coalesce(max(public_number),0)+1 FROM room_threads WHERE room_id='default'").fetchone()[0]
                db.execute("INSERT INTO room_threads(room_id,label,storage_key,creator,created,public_number) VALUES ('default',?,?,?,?,?)", (thread,thread,sender,now,number))
                room_thread = db.execute("SELECT * FROM room_threads WHERE room_id='default' AND label=?", (thread,)).fetchone()
            db.execute('UPDATE room_threads SET used=used+1 WHERE number=?', (room_thread['number'],))
            public_id = db.execute("SELECT coalesce(max(public_id),0)+1 FROM messages WHERE room_id='default'").fetchone()[0]
            db.execute('UPDATE messages SET bytes=?,thread_no=?,public_id=? WHERE id=?', (size,room_thread['number'],public_id,cursor.lastrowid))
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
                rows = db.execute("SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id='default' AND m.public_id>? AND "
                                  "EXISTS(SELECT 1 FROM deliveries d WHERE d.room_id='default' AND d.message_id=m.id AND d.member=?) ORDER BY m.public_id LIMIT ?",
                                  (after, actual['name'], limit)).fetchall()
            else:
                rows = db.execute("SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id='default' AND m.public_id>? ORDER BY m.public_id LIMIT ?",
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
        if name.casefold() in ('human','relay') or role not in ('agent','monitor'):
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
        return {'id':row['public_id'],'room':row['room_id'],'thread':row['label'],
                'from':row['sender'],'to':to,'ts':row['created'],'source':row['source'],
                'untrusted':True,'text':row['text']}

    def _room_send(self, p, room, to, thread, text, human=False, state_version=None):
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
            if not human:
                self._sync_check_write(db,room,state_version)
            if thread == '__relay_sync__':
                raise DomainError(400,'reserved system thread')
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
                number = db.execute('SELECT coalesce(max(public_number),0)+1 FROM room_threads WHERE room_id=?',(room,)).fetchone()[0]
                db.execute('INSERT INTO room_threads(room_id,label,storage_key,creator,created,public_number) VALUES (?,?,?,?,?,?)',(room,thread,key,sender,now,number))
                t = db.execute('SELECT * FROM room_threads WHERE room_id=? AND label=?',(room,thread)).fetchone()
            if not human and t['used']>=self.thread_budget:
                raise DomainError(409,'thread budget exhausted; admin reset required')
            public_id = db.execute('SELECT coalesce(max(public_id),0)+1 FROM messages WHERE room_id=?',(room,)).fetchone()[0]
            cur = db.execute('INSERT INTO messages(sender,recipient,thread,text,created,room_id,source,bytes,thread_no,public_id) VALUES (?,?,?,?,?,?,?,?,?,?)',
                (sender,json.dumps(recipients),t['storage_key'],text,now,room,'human' if human else 'agent',size,t['number'],public_id))
            db.executemany('INSERT INTO deliveries(room_id,message_id,member) VALUES (?,?,?)',[(room,cur.lastrowid,n) for n in set(recipients+[sender])])
            if not human:
                db.execute('UPDATE room_threads SET used=used+1 WHERE number=?',(t['number'],))
            else:
                self._event(db,room,actor['name'],'inject',str(cur.lastrowid))
            row = db.execute('SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id=? AND m.id=?',(room,cur.lastrowid)).fetchone()
            return self._envelope(row)

    def room_post(self, p, room, to, thread, text, state_version=None):
        return self._room_send(p,room,to,thread,text,state_version=state_version)

    def inject(self, admin, room, to, thread, text):
        return self._room_send(admin,room,to,thread,text,human=True)

    def room_fetch(self, p, room, after=0, limit=100):
        _integer(after,'after')
        _integer(limit,'limit',1,1000)
        with self.store.transaction(read_only=True) as db:
            actor = self._room_auth(db,p,room,'content')
            sql = 'SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id=? AND m.public_id>? '
            args = [room,after]
            if actor['role']=='agent':
                sql += 'AND EXISTS(SELECT 1 FROM deliveries d WHERE d.room_id=m.room_id AND d.message_id=m.id AND d.member=?) '
                args.append(actor['name'])
            return [self._envelope(r) for r in db.execute(sql+'ORDER BY m.public_id LIMIT ?',(*args,limit))]

    def monitor(self, p, room, after=0, limit=100):
        _integer(after,'after')
        _integer(limit,'limit',1,1000)
        with self.store.transaction(read_only=True) as db:
            self._room_auth(db,p,room,'metadata')
            return [dict(r) for r in db.execute('SELECT m.public_id AS id,m.created AS ts,m.sender AS "from",m.room_id AS room,m.bytes,m.source,t.public_number AS thread_no, '
                '(SELECT count(*) FROM deliveries d WHERE d.room_id=m.room_id AND d.message_id=m.id AND d.member!=m.sender) AS to_count '
                'FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.room_id=? AND m.public_id>? ORDER BY m.public_id LIMIT ?',(room,after,limit))]

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

    # Synchronization decisions and their notices share the room transaction.
    # An aborted version is consumed forever, so delayed acks cannot approve
    # different content. Presence never changes an enrollment snapshot.
    @staticmethod
    def _sync_config(db, room, now=None):
        if not db.execute('SELECT 1 FROM rooms WHERE id=?',(room,)).fetchone():
            raise DomainError(404,'no such room')
        db.execute('INSERT OR IGNORE INTO sync_rooms(room_id,started) VALUES (?,?)',
                   (room,time.time() if now is None else now))
        return dict(db.execute('SELECT * FROM sync_rooms WHERE room_id=?',(room,)).fetchone())

    @staticmethod
    def _sync_open(db, room):
        row = db.execute("SELECT * FROM sync_versions WHERE room_id=? AND status='open'",(room,)).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _sync_enrolled(db, room, version):
        return [dict(r) for r in db.execute('SELECT name,generation,acked FROM sync_enrollments WHERE room_id=? AND version=? ORDER BY name',(room,version))]

    @staticmethod
    def _sync_text(value, field, limit, empty=True):
        if not isinstance(value,str) or (not empty and not value.strip()):
            raise DomainError(400,'invalid '+field)
        try:
            size = len(value.encode('utf-8'))
        except UnicodeEncodeError:
            raise DomainError(400,field+' must be valid Unicode') from None
        if size>limit or '\x00' in value:
            raise DomainError(400,field+' exceeds limit or contains NUL')
        return value

    @staticmethod
    def _sync_duration(value, default=300):
        return default if value is None else _integer(value,'deadline_seconds',1,86400)

    def _sync_actor(self, db, p, room, write=False):
        actor = self._room_auth(db,p,room,'write' if write else 'content')
        if actor['role'] not in ('agent','admin'):
            raise DomainError(403,'agent or administrator required')
        return actor

    def _sync_tick(self, p, room, write=False):
        # Persist expirations even when the following mutation returns a 409.
        with self.store.transaction(read_only=True) as db:
            self._sync_actor(db,p,room,write)
        self.sync_scan(room)

    @staticmethod
    def _sync_check_write(db, room, version):
        cfg = db.execute('SELECT strict,version FROM sync_rooms WHERE room_id=?',(room,)).fetchone()
        if cfg and cfg['strict'] and (type(version) is not int or version!=cfg['version']):
            err = DomainError(409,'state_version must match current committed version')
            err.current_version = cfg['version']
            err.drift = True
            raise err

    def _sync_start(self, db, room, cfg, state, phase, names, proposer, now, duration, implicit=True):
        if not isinstance(names,list) or not 1<=len(names)<=1000 or len(set(n for n in names if isinstance(n,str)))!=len(names):
            raise DomainError(400,'enrolled must contain unique agent names')
        snapshots = []
        for name in names:
            _name(name)
            row = db.execute("SELECT name,generation FROM room_members WHERE room_id=? AND name=? AND active=1 AND role='agent'",(room,name)).fetchone()
            if row is None:
                raise DomainError(400,'enrolled member must be an active room agent')
            snapshots.append((row['name'],row['generation']))
        if implicit and proposer not in names:
            raise DomainError(400,'proposer must be enrolled')
        version = cfg['allocated']+1
        db.execute('UPDATE sync_rooms SET allocated=?,enabled=1,fingerprint=NULL,stalled_kind=NULL,stalled_members=NULL,stalled_since=NULL,notice_count=0,next_notice=NULL WHERE room_id=?',(version,room))
        db.execute('INSERT INTO sync_versions VALUES (?,?,?,?,?,?,?,?,?,?)',
                   (room,version,cfg['version'],phase,state,proposer,now,now+duration,'open',None))
        db.executemany('INSERT INTO sync_enrollments VALUES (?,?,?,?,?)',
                       [(room,version,n,g,now if implicit and n==proposer else None) for n,g in snapshots])
        self._event(db,room,proposer,'sync-propose',str(version))
        self._sync_commit(db,room,version,now)
        return version

    def _sync_commit(self, db, room, version, now):
        if db.execute('SELECT 1 FROM sync_enrollments WHERE room_id=? AND version=? AND acked IS NULL',(room,version)).fetchone():
            return
        # A rotated/revoked participant cannot be counted from an old ack.
        if db.execute("SELECT 1 FROM sync_enrollments e LEFT JOIN room_members m ON m.room_id=e.room_id AND m.name=e.name WHERE e.room_id=? AND e.version=? AND (m.name IS NULL OR m.active!=1 OR m.role!='agent' OR m.generation!=e.generation)",(room,version)).fetchone():
            return
        db.execute("UPDATE sync_versions SET status='committed',ended=? WHERE room_id=? AND version=?",(now,room,version))
        db.execute('UPDATE sync_rooms SET version=?,fingerprint=NULL,stalled_kind=NULL,stalled_members=NULL,stalled_since=NULL,notice_count=0,next_notice=NULL WHERE room_id=?',(version,room))
        self._event(db,room,'relay','sync-commit',str(version))

    def _sync_view(self, db, room, content=False):
        cfg = self._sync_config(db,room)
        pending = self._sync_open(db,room)
        current = db.execute('SELECT * FROM sync_versions WHERE room_id=? AND version=?',(room,cfg['version'])).fetchone()
        version = pending['version'] if pending else cfg['version']
        enrolled = self._sync_enrolled(db,room,version) if version else []
        if not enrolled:
            enrolled = [dict(r) for r in db.execute("SELECT name,generation,NULL AS acked FROM room_members WHERE room_id=? AND active=1 AND role='agent' ORDER BY name",(room,))]
        statuses = {r['name']:dict(r) for r in db.execute('SELECT s.* FROM sync_statuses s JOIN room_members m ON m.room_id=s.room_id AND m.name=s.name AND m.generation=s.generation AND m.active=1 WHERE s.room_id=?',(room,))}
        acks, drift = {}, []
        for member in enrolled:
            name = member['name']
            ack = db.execute("SELECT e.version,e.acked FROM sync_enrollments e JOIN sync_versions v ON v.room_id=e.room_id AND v.version=e.version WHERE e.room_id=? AND e.name=? AND e.generation=? AND e.acked IS NOT NULL AND v.status='committed' ORDER BY e.version DESC LIMIT 1",(room,name,member['generation'])).fetchone()
            status = statuses.get(name)
            known = ack['version'] if ack else None
            if known is None and cfg['version']==0:
                known = 0
            if status and (ack is None or status['declared']>ack['acked']):
                known = status['state_version']
            acks[name] = known
            if known!=cfg['version']:
                drift.append(name)
        unacked = []
        if pending:
            for e in enrolled:
                member = db.execute('SELECT active,generation FROM room_members WHERE room_id=? AND name=?',(room,e['name'])).fetchone()
                if e['acked'] is None or member is None or not member['active'] or member['generation']!=e['generation']:
                    unacked.append(e['name'])
        round_view = None
        if pending:
            round_view = {k:pending[k] for k in ('version','base_version','created','deadline')}
            round_view.update(enrolled=[e['name'] for e in enrolled],acked=[e['name'] for e in enrolled if e['name'] not in unacked])
            if content:
                round_view.update(phase=pending['phase'],state=pending['state'])
        result = {'version':cfg['version'],'round':round_view,'round_open':pending is not None,
                  'unacked':unacked,'acks':acks,'drift':drift,'stalled':bool(cfg['stalled_kind']),
                  'kind':cfg['stalled_kind'],'since':cfg['stalled_since'],
                  'members':json.loads(cfg['stalled_members'] or '[]'),
                  'waiting_on':{name:s['waiting_on'] for name,s in statuses.items()},
                  'strict':bool(cfg['strict']),'auto_pass':bool(cfg['auto_pass']),
                  'stall_seconds':cfg['stall_seconds'],'turn':cfg['turn'],
                  'turn_version':cfg['turn_version'],'turn_since':cfg['turn_since']}
        if content:
            result.update(phase=current['phase'] if current else '',state=current['state'] if current else '',
                          statuses=[{k:s[k] for k in ('name','state_version','waiting_on','reason','declared','deadline')} for s in statuses.values()])
        return result

    def sync_state(self, p, room):
        self._sync_tick(p,room)
        with self.store.transaction() as db:
            self._sync_actor(db,p,room)
            return self._sync_view(db,room,True)

    def sync_monitor(self, p, room):
        with self.store.transaction() as db:
            self._room_auth(db,p,room,'metadata')
            return self._sync_view(db,room)

    def sync_summary(self, p, room):
        with self.store.transaction() as db:
            self._room_auth(db,p,room)
            view = self._sync_view(db,room)
            return {k:view[k] for k in ('version','round_open','unacked','stalled','strict')}

    def sync_enabled_rooms(self):
        """Internal watcher inventory; idle rooms never cause notice traffic."""
        with self.store.transaction(read_only=True) as db:
            return [r[0] for r in db.execute("SELECT s.room_id FROM sync_rooms s JOIN rooms r ON r.id=s.room_id WHERE s.enabled=1 AND r.status='open' ORDER BY s.room_id")]

    def sync_propose(self, p, room, base_version, state, phase=None, enrolled=None, deadline_seconds=None):
        _integer(base_version,'base_version')
        self._sync_text(state,'state',4096)
        phase = '' if phase is None else _string(phase,'phase',64)
        duration = self._sync_duration(deadline_seconds)
        self._sync_tick(p,room,True)
        with self.store.transaction() as db:
            actor = self._sync_actor(db,p,room,True)
            cfg = self._sync_config(db,room)
            if base_version!=cfg['version'] or self._sync_open(db,room):
                raise DomainError(409,'stale base_version or round already open')
            names = enrolled if enrolled is not None else [r[0] for r in db.execute("SELECT name FROM room_members WHERE room_id=? AND active=1 AND role='agent' ORDER BY name",(room,))]
            now = time.time()
            if db.execute('SELECT count(*) FROM sync_versions WHERE room_id=? AND proposer=? AND created>?',(room,actor['name'],now-3600)).fetchone()[0]>=self.hourly_messages:
                raise DomainError(429,'hourly proposal budget exhausted')
            self._sync_start(db,room,cfg,state,phase,names,actor['name'],now,duration)
            return self._sync_view(db,room,True)

    def _sync_vote(self, p, room, version, reason=None):
        _integer(version,'version',1)
        if reason is not None:
            self._sync_text(reason,'reason',200,False)
        self._sync_tick(p,room,True)
        with self.store.transaction() as db:
            actor = self._sync_actor(db,p,room,True)
            pending = self._sync_open(db,room)
            if pending is None or pending['version']!=version or time.time()>=pending['deadline']:
                raise DomainError(409,'no matching open round')
            e = db.execute('SELECT * FROM sync_enrollments WHERE room_id=? AND version=? AND name=?',(room,version,actor['name'])).fetchone()
            m = db.execute('SELECT generation FROM room_members WHERE room_id=? AND name=?',(room,actor['name'])).fetchone()
            if e is None or e['generation']!=m['generation']:
                raise DomainError(403,'not enrolled with this credential generation')
            now = time.time()
            if reason is None:
                db.execute('UPDATE sync_enrollments SET acked=coalesce(acked,?) WHERE room_id=? AND version=? AND name=?',(now,room,version,actor['name']))
                self._sync_commit(db,room,version,now)
            else:
                db.execute("UPDATE sync_versions SET status='nacked',ended=? WHERE room_id=? AND version=?",(now,room,version))
                self._event(db,room,actor['name'],'sync-nack',str(version))
            return self._sync_view(db,room,True)

    def sync_ack(self, p, room, version):
        return self._sync_vote(p,room,version)

    def sync_nack(self, p, room, version, reason):
        return self._sync_vote(p,room,version,reason)

    def sync_status(self, p, room, state_version, waiting_on=None, reason='', deadline_seconds=None):
        _integer(state_version,'state_version')
        self._sync_text(reason,'reason',200)
        duration = None if deadline_seconds is None else self._sync_duration(deadline_seconds)
        with self.store.transaction() as db:
            actor = self._sync_actor(db,p,room,True)
            cfg = self._sync_config(db,room)
            if state_version!=0 and not db.execute("SELECT 1 FROM sync_versions WHERE room_id=? AND version=? AND status='committed'",(room,state_version)).fetchone():
                raise DomainError(409,'status must declare a committed version')
            if waiting_on is not None:
                _name(waiting_on)
                if waiting_on==actor['name'] or (waiting_on!='human' and not db.execute("SELECT 1 FROM room_members WHERE room_id=? AND name=? AND active=1 AND role='agent'",(room,waiting_on)).fetchone()):
                    raise DomainError(400,'waiting_on must be another room agent or human')
            now = time.time()
            generation = db.execute('SELECT generation FROM room_members WHERE room_id=? AND name=?',(room,actor['name'])).fetchone()[0]
            old = db.execute('SELECT * FROM sync_statuses WHERE room_id=? AND name=?',(room,actor['name'])).fetchone()
            # Repeating the same waiting edge must not reset its stall clock.
            declared = old['declared'] if old and old['generation']==generation and old['state_version']==state_version and old['waiting_on']==waiting_on and waiting_on is not None else now
            db.execute('INSERT OR REPLACE INTO sync_statuses VALUES (?,?,?,?,?,?,?,?)',
                       (room,actor['name'],generation,state_version,waiting_on,reason,declared,now+duration if duration else None))
            db.execute('UPDATE sync_rooms SET enabled=1 WHERE room_id=?',(room,))
        self.sync_scan(room)
        return self.sync_state(p,room)

    def sync_wait(self, p, room, waiting=True):
        if type(waiting) is not bool:
            raise DomainError(400,'waiting must be boolean')
        with self.store.lock:
            if not isinstance(p,dict):
                raise DomainError(403,'invalid principal')
            _name(room)
            _name(p.get('name'))
            if waiting:
                with self.store.transaction(read_only=True) as db:
                    self._sync_actor(db,p,room)
            # Closing an already registered wait must work after revocation.
            key = (room,p['name'],p.get('generation',0))
            count,since = self._sync_waits.get(key,(0,time.time()))
            if waiting:
                self._sync_waits[key] = (count+1,since)
            elif count>1:
                self._sync_waits[key] = (count-1,since)
            else:
                self._sync_waits.pop(key,None)

    def sync_abort(self, admin, room):
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            pending = self._sync_open(db,room)
            if pending:
                db.execute("UPDATE sync_versions SET status='aborted',ended=? WHERE room_id=? AND version=?",(time.time(),room,pending['version']))
            db.execute('UPDATE sync_rooms SET fingerprint=NULL,stalled_kind=NULL,stalled_members=NULL,stalled_since=NULL,next_notice=NULL,notice_count=0 WHERE room_id=?',(room,))
            self._event(db,room,actor['name'],'sync-abort',str(pending['version']) if pending else '')
            return self._sync_view(db,room)

    def sync_remove(self, admin, room, name):
        _name(name)
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            cfg = self._sync_config(db,room)
            pending = self._sync_open(db,room)
            if pending is None:
                raise DomainError(409,'no open round')
            names = [e['name'] for e in self._sync_enrolled(db,room,pending['version'])]
            if name not in names or len(names)==1:
                raise DomainError(400,'removal must leave at least one enrolled participant')
            now = time.time()
            db.execute("UPDATE sync_versions SET status='removed',ended=? WHERE room_id=? AND version=?",(now,room,pending['version']))
            self._sync_start(db,room,cfg,pending['state'],pending['phase'],[n for n in names if n!=name],actor['name'],now,self._sync_duration(None),False)
            self._event(db,room,actor['name'],'sync-remove',name)
            self._system_notice(db,room,'*','Synchronization participant removed: '+name,now)
            return self._sync_view(db,room)

    def sync_reset(self, admin, room, version):
        _integer(version,'version')
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            cfg = self._sync_config(db,room)
            if self._sync_open(db,room):
                raise DomainError(409,'abort the open round before reset')
            old = db.execute("SELECT state,phase FROM sync_versions WHERE room_id=? AND version=? AND status='committed'",(room,version)).fetchone()
            if version!=0 and old is None:
                raise DomainError(404,'no such committed version')
            names = [r[0] for r in db.execute("SELECT name FROM room_members WHERE room_id=? AND active=1 AND role='agent' ORDER BY name",(room,))]
            self._sync_start(db,room,cfg,old['state'] if old else '',old['phase'] if old else '',names,actor['name'],time.time(),300,False)
            self._event(db,room,actor['name'],'sync-reset',str(version))
            return self._sync_view(db,room)

    _TURN_UNSET = object()

    def set_room_sync(self, admin, room, strict=None, auto_pass=None, stall_seconds=None, turn=_TURN_UNSET):
        for value in (strict,auto_pass):
            if value is not None and type(value) is not bool:
                raise DomainError(400,'sync flags must be boolean')
        if stall_seconds is not None:
            _integer(stall_seconds,'stall_seconds',5,86400)
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            self._sync_config(db,room)
            for key,value in (('strict',strict),('auto_pass',auto_pass),('stall_seconds',stall_seconds)):
                if value is not None:
                    db.execute('UPDATE sync_rooms SET '+key+'=?,enabled=1 WHERE room_id=?',(value,room))
            if turn is not self._TURN_UNSET:
                if turn is not None:
                    _name(turn)
                    if not db.execute("SELECT 1 FROM room_members WHERE room_id=? AND name=? AND active=1 AND role='agent'",(room,turn)).fetchone():
                        raise DomainError(400,'turn must name an active room agent')
                now = time.time()
                db.execute('UPDATE sync_rooms SET turn=?,turn_since=?,turn_version=turn_version+1,enabled=1 WHERE room_id=?',(turn,now,room))
                self._system_notice(db,room,'*','Scheduling turn set to '+(turn or 'none'),now)
            self._event(db,room,actor['name'],'sync-config')
            return self._sync_view(db,room)

    def _system_notice(self, db, room, to, text, now):
        cfg = self._sync_config(db,room,now)
        if now-cfg['notice_hour']>=3600:
            db.execute('UPDATE sync_rooms SET notice_hour=?,hour_count=0 WHERE room_id=?',(now,room))
            cfg['hour_count'] = 0
        if cfg['hour_count']>=20:
            return None
        names = [r[0] for r in db.execute("SELECT name FROM room_members WHERE room_id=? AND active=1 AND role='agent' ORDER BY name",(room,))]
        if to!='*':
            if not isinstance(to,list):
                raise DomainError(400,'invalid system recipients')
            names = [n for n in names if n in to]
        if not names:
            return None
        if len(text.encode('utf-8'))>8192:
            text = text.encode('utf-8')[:8189].decode('utf-8','ignore')+'...'
        label = '__relay_sync__'
        t = db.execute('SELECT * FROM room_threads WHERE room_id=? AND label=?',(room,label)).fetchone()
        if t is None:
            key = 'system-'+secrets.token_hex(24)
            db.execute('INSERT INTO threads(id,participant_a,participant_b,creator,created,room_id) VALUES (?,?,?,?,?,?)',(key,'relay',names[0],'relay',now,room))
            number = db.execute('SELECT coalesce(max(public_number),0)+1 FROM room_threads WHERE room_id=?',(room,)).fetchone()[0]
            db.execute('INSERT INTO room_threads(room_id,label,storage_key,creator,created,public_number) VALUES (?,?,?,?,?,?)',(room,label,key,'relay',now,number))
            t = db.execute('SELECT * FROM room_threads WHERE room_id=? AND label=?',(room,label)).fetchone()
        public_id = db.execute('SELECT coalesce(max(public_id),0)+1 FROM messages WHERE room_id=?',(room,)).fetchone()[0]
        mid = db.execute('INSERT INTO messages(sender,recipient,thread,text,created,room_id,source,bytes,thread_no,public_id) VALUES (?,?,?,?,?,?,?,?,?,?)',
                         ('relay',json.dumps(names),t['storage_key'],text,now,room,'system',len(text.encode('utf-8')),t['number'],public_id)).lastrowid
        db.executemany('INSERT INTO deliveries VALUES (?,?,?)',[(room,mid,n) for n in names])
        db.execute('UPDATE sync_rooms SET hour_count=hour_count+1 WHERE room_id=?',(room,))
        row = db.execute('SELECT m.*,t.label FROM messages m JOIN room_threads t ON t.number=m.thread_no WHERE m.id=?',(mid,)).fetchone()
        return self._envelope(row)

    def system_notice(self, room, to, text):
        # Internal only: no public route may accept arbitrary system notices.
        _name(room)
        self._sync_text(text,'system notice',8192,False)
        with self.store.transaction() as db:
            return self._system_notice(db,room,to,text,time.time())

    def sync_scan(self, room, now=None):
        _name(room)
        now = time.time() if now is None else now
        if type(now) not in (int,float) or not math.isfinite(now):
            raise DomainError(400,'invalid scan time')
        with self.store.transaction() as db:
            cfg = self._sync_config(db,room,now)
            pending = self._sync_open(db,room)
            kind, involved = None, []
            version = pending['version'] if pending else cfg['version']
            enrolled = self._sync_enrolled(db,room,version) if version else []
            names = [e['name'] for e in enrolled] or [r[0] for r in db.execute("SELECT name FROM room_members WHERE room_id=? AND active=1 AND role='agent' ORDER BY name",(room,))]
            statuses = {r['name']:dict(r) for r in db.execute('SELECT s.* FROM sync_statuses s JOIN room_members m ON m.room_id=s.room_id AND m.name=s.name AND m.generation=s.generation AND m.active=1 WHERE s.room_id=?',(room,)) if r['name'] in names}
            if pending and now>=pending['deadline']:
                involved = [e['name'] for e in enrolled if e['acked'] is None]
                kind = 'silent' if involved else 'deadline'
                db.execute("UPDATE sync_versions SET status='expired',ended=? WHERE room_id=? AND version=?",(now,room,version))
                self._event(db,room,'relay','sync-expire',str(version))
            elif cfg['stalled_kind'] in ('silent','deadline') and pending is None:
                latest = db.execute('SELECT status,version FROM sync_versions WHERE room_id=? ORDER BY version DESC LIMIT 1',(room,)).fetchone()
                if latest and latest['status']=='expired':
                    version = latest['version']
                    kind,involved = cfg['stalled_kind'],json.loads(cfg['stalled_members'] or '[]')
            if kind is None:
                expired = [n for n,s in statuses.items() if s['deadline'] is not None and now>=s['deadline']]
                if expired:
                    kind,involved = 'deadline',sorted(expired)
            if kind is None:
                cycles = set()
                for start in names:
                    path, node = [], start
                    while node in statuses and node not in path:
                        path.append(node)
                        node = statuses[node]['waiting_on']
                    if node in path:
                        cycles.update(path[path.index(node):])
                if cycles:
                    kind,involved = 'cycle',sorted(cycles)
            if kind is None and names:
                last_traffic = db.execute("SELECT max(created) FROM messages WHERE room_id=? AND source!='system'",(room,)).fetchone()[0]
                waiting = []
                for n in names:
                    s = statuses.get(n)
                    generation = db.execute('SELECT generation FROM room_members WHERE room_id=? AND name=? AND active=1',(room,n)).fetchone()
                    open_wait = self._sync_waits.get((room,n,generation[0])) if generation else None
                    if open_wait is None and room=='default' and generation:
                        open_wait = self._sync_waits.get((room,n,0))
                    if s and s['waiting_on'] is not None and now-s['declared']>=cfg['stall_seconds']:
                        waiting.append(n)
                    elif open_wait and now-max(open_wait[1],last_traffic or cfg['started'])>=cfg['stall_seconds']:
                        waiting.append(n)
                if len(waiting)==len(names):
                    kind,involved = 'all_waiting',names
            room_open = db.execute('SELECT status FROM rooms WHERE id=?',(room,)).fetchone()[0]=='open'
            if not cfg['enabled'] or not room_open:
                kind,involved = None,[]
            fingerprint = json.dumps([kind,sorted(involved),version]) if kind else None
            same = fingerprint is not None and fingerprint==cfg['fingerprint']
            since = cfg['stalled_since'] if same else now if kind else None
            count = cfg['notice_count'] if same else 0
            due = kind and count<5 and (not same or cfg['next_notice'] is None or now>=cfg['next_notice'])
            notice = None
            passed = False
            if due and cfg['auto_pass'] and cfg['turn'] in involved and now-(cfg['turn_since'] if cfg['turn_since'] is not None else now)>=cfg['stall_seconds'] and now-(cfg['last_pass'] if cfg['last_pass'] is not None else cfg['started'])>=cfg['stall_seconds'] and (now-cfg['notice_hour']>=3600 or cfg['hour_count']<20):
                active = [r[0] for r in db.execute("SELECT name FROM room_members WHERE room_id=? AND active=1 AND role='agent' ORDER BY name",(room,)) if r[0] in names]
                if len(active)>1 and cfg['turn'] in active:
                    turn = active[(active.index(cfg['turn'])+1)%len(active)]
                    db.execute('UPDATE sync_rooms SET turn=?,turn_since=?,turn_version=turn_version+1,last_pass=? WHERE room_id=?',(turn,now,now,room))
                    self._event(db,room,'relay','sync-pass',turn)
                    passed = True
            if due:
                text = 'Synchronization stalled ('+kind+'): '+', '.join(involved)
                if passed:
                    text += '; scheduling turn passed to '+turn
                notice = self._system_notice(db,room,names,text,now)
                # Reserve an attempt even at the hourly cap; scans cannot spin.
                count += 1
            next_notice = now+min(60*2**max(count-1,0),960) if due else cfg['next_notice'] if same else None
            db.execute('UPDATE sync_rooms SET fingerprint=?,stalled_kind=?,stalled_members=?,stalled_since=?,notice_count=?,next_notice=? WHERE room_id=?',
                       (fingerprint,kind,json.dumps(sorted(involved)),since,count,next_notice,room))
            return {'stalled':bool(kind),'kind':kind,'members':sorted(involved),'since':since,'notify':notice is not None,'notice':notice}

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
        if type(thread) is int:
            _integer(thread,'thread number',1)
            selector = 'public_number'
        else:
            _string(thread,'thread',128)
            selector = 'label'
        with self.store.transaction() as db:
            actor = self._admin(db,admin)
            self._room_auth(db,admin,room)
            cur = db.execute('UPDATE room_threads SET used=0 WHERE room_id=? AND '+selector+'=?',(room,thread))
            if not cur.rowcount:
                raise DomainError(404,'no such thread')
            if room=='default':
                db.execute('UPDATE threads SET used=0 WHERE id IN (SELECT storage_key FROM room_threads WHERE room_id=? AND '+selector+'=?)',(room,thread))
            self._event(db,room,actor['name'],'reset-thread')

    @staticmethod
    def _session_hash(session):
        if not isinstance(session,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',session):
            return None
        return hashlib.sha256(session.encode('ascii')).hexdigest()

    @staticmethod
    def _csrf(db, session):
        key = db.execute("SELECT value FROM settings WHERE key='web_csrf_key'").fetchone()[0]
        return hmac.new(bytes.fromhex(key),session.encode('ascii'),hashlib.sha256).hexdigest()

    @staticmethod
    def _live_session(db, digest, now):
        return db.execute("SELECT s.* FROM sessions s JOIN agents a ON a.name=s.admin_name "
            "WHERE s.session_hash=? AND a.active=1 AND a.role='admin' AND a.token_hash=s.credential_hash "
            "AND s.expires_at>? AND s.last_seen>?",(digest,now,now-1800)).fetchone()

    @staticmethod
    def _purge_web(db, now):
        sessions = db.execute("DELETE FROM sessions WHERE expires_at<=? OR last_seen<=? OR NOT EXISTS "
            "(SELECT 1 FROM agents a WHERE a.name=sessions.admin_name AND a.active=1 AND a.role='admin' AND a.token_hash=sessions.credential_hash)",
            (now,now-1800)).rowcount
        attempts = db.execute('DELETE FROM login_attempts WHERE attempted<=?',(now-3600,)).rowcount
        return {'sessions':sessions,'attempts':attempts}

    def session_create(self, token_hash, client_key):
        """Authenticate and atomically apply persisted failure throttles.

        Invalid credentials commit their failure row before the generic 401 is
        raised. No submitted credential or credential hash is logged on failure.
        """
        _string(client_key,'client address',256)
        peer = hashlib.sha256(('peer:'+client_key).encode()).hexdigest()
        now = time.time()
        failed = False
        with self.store.transaction() as db:
            self._purge_web(db,now)
            retry = 0
            for condition,args,window,limit in [
                ('peer_hash=? AND attempted>?',(peer,now-900),900,5),
                ('attempted>?',(now-3600,),3600,30),
            ]:
                row = db.execute('SELECT count(*),min(attempted) FROM login_attempts WHERE '+condition,args).fetchone()
                if row[0]>=limit:
                    retry = max(retry,max(1,math.ceil(row[1]+window-now)))
            if retry:
                error = DomainError(429,'login temporarily rate limited')
                error.retry_after = retry
                raise error
            admin = None
            if isinstance(token_hash,str) and re.fullmatch(r'[0-9a-f]{64}',token_hash):
                admin = db.execute("SELECT name,token_hash FROM agents WHERE token_hash=? AND role='admin' AND active=1",(token_hash,)).fetchone()
            if admin is None:
                db.execute('INSERT INTO login_attempts(peer_hash,attempted) VALUES (?,?)',(peer,now))
                failed = True
            else:
                session = secrets.token_urlsafe(32)
                expires = now+28800
                db.execute('INSERT INTO sessions(session_hash,admin_name,credential_hash,created,last_seen,expires_at,peer_hash) VALUES (?,?,?,?,?,?,?)',
                    (self._session_hash(session),admin['name'],admin['token_hash'],now,now,expires,peer))
                result = {'session':session,'csrf':self._csrf(db,session),'expires_at':expires}
        if failed:
            raise DomainError(401,'invalid credentials')
        return result

    def session_validate(self, session, csrf=None, mutation=False):
        digest = self._session_hash(session)
        if digest is None:
            return None
        if type(mutation) is not bool:
            raise DomainError(400,'invalid mutation flag')
        now = time.time()
        with self.store.transaction(read_only=True) as db:
            row = self._live_session(db,digest,now)
            if row is None:
                return None
            expected = self._csrf(db,session)
            if mutation and (not isinstance(csrf,str) or not re.fullmatch(r'[0-9a-f]{64}',csrf) or not hmac.compare_digest(csrf,expected)):
                raise DomainError(403,'invalid CSRF token')
            touch = row['last_seen']<=now-60
            result = {'principal':{'name':row['admin_name'],'role':'admin','room':None,'generation':1},
                      'expires_at':row['expires_at'],'csrf':expected}
        if touch:
            with self.store.transaction() as db:
                # Recheck expiry and the bound admin credential under the write lock.
                row = self._live_session(db,digest,now)
                if row is None:
                    return None
                db.execute('UPDATE sessions SET last_seen=max(last_seen,?) WHERE session_hash=?',(now,digest))
        return result

    def session_revoke(self, session):
        digest = self._session_hash(session)
        if digest is None:
            return 0
        with self.store.transaction() as db:
            return db.execute('DELETE FROM sessions WHERE session_hash=?',(digest,)).rowcount

    def session_revoke_all(self, session):
        digest = self._session_hash(session)
        now = time.time()
        with self.store.transaction() as db:
            row = self._live_session(db,digest,now) if digest else None
            if row is None:
                raise DomainError(401,'invalid session')
            return db.execute('DELETE FROM sessions WHERE admin_name=?',(row['admin_name'],)).rowcount

    def session_purge(self):
        with self.store.transaction() as db:
            return self._purge_web(db,time.time())
