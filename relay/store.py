"""SQLite persistence. All domain read/check/write operations share a transaction."""
from contextlib import contextmanager
import sqlite3
import threading
from pathlib import Path
import time
import secrets


SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    name TEXT PRIMARY KEY, role TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO settings VALUES ('paused', '0');
CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY, participant_a TEXT NOT NULL, participant_b TEXT NOT NULL,
    creator TEXT NOT NULL, created REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL,
    recipient TEXT NOT NULL, thread TEXT NOT NULL REFERENCES threads(id),
    text TEXT NOT NULL, created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_sender_time ON messages(sender, created);
CREATE INDEX IF NOT EXISTS threads_creator_time ON threads(creator, created);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL,
    title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', branch TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS claims (
    task_id INTEGER NOT NULL REFERENCES tasks(id), path TEXT NOT NULL,
    display_path TEXT,
    PRIMARY KEY(task_id, path)
);
"""

ROOM_SCHEMA = """
CREATE TABLE IF NOT EXISTS rooms (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 created REAL NOT NULL, creator TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS room_members (
 room_id TEXT NOT NULL REFERENCES rooms(id), name TEXT NOT NULL, role TEXT NOT NULL,
 token_hash TEXT UNIQUE NOT NULL, active INTEGER NOT NULL DEFAULT 1,
 generation INTEGER NOT NULL DEFAULT 1, last_seen REAL,
 PRIMARY KEY(room_id,name)
);
CREATE TABLE IF NOT EXISTS room_threads (
 number INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT NOT NULL REFERENCES rooms(id),
 label TEXT NOT NULL, storage_key TEXT UNIQUE NOT NULL, creator TEXT NOT NULL,
 created REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0, legacy_a TEXT, legacy_b TEXT,
 UNIQUE(room_id,label)
);
CREATE TABLE IF NOT EXISTS deliveries (
 room_id TEXT NOT NULL REFERENCES rooms(id), message_id INTEGER NOT NULL REFERENCES messages(id),
 member TEXT NOT NULL, PRIMARY KEY(room_id,message_id,member)
);
CREATE TABLE IF NOT EXISTS room_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT NOT NULL REFERENCES rooms(id),
 actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS delivery_reader ON deliveries(room_id,member,message_id);
CREATE INDEX IF NOT EXISTS room_messages ON messages(room_id,id);
"""

WEB_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
 session_hash TEXT PRIMARY KEY, admin_name TEXT NOT NULL REFERENCES agents(name),
 credential_hash TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL,
 expires_at REAL NOT NULL, peer_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS session_admin ON sessions(admin_name);
CREATE TABLE IF NOT EXISTS login_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, peer_hash TEXT NOT NULL, attempted REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS login_peer_time ON login_attempts(peer_hash,attempted);
CREATE INDEX IF NOT EXISTS login_global_time ON login_attempts(attempted);
"""


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(str(path), check_same_thread=False,
                                          isolation_level=None, timeout=10)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA foreign_keys=ON')
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('PRAGMA synchronous=FULL')
        try:
            self._initialize(path)
        except BaseException:
            self.connection.close()
            raise

    def _initialize(self, path):
        tables = {r[0] for r in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        version = None
        if 'settings' in tables:
            row = self.connection.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
            version = int(row[0]) if row else None
        if version is not None and version > 3:
            raise RuntimeError('database schema is newer than this relay supports')
        if tables and version != 3 and str(path) != ':memory:':
            backup = Path(str(path) + ('.v2.bak' if version==2 else '.v1.bak'))
            if not backup.exists():
                # SQLite backup includes committed WAL pages, unlike copying the main file.
                target = sqlite3.connect(str(backup))
                try:
                    self.connection.backup(target)
                finally:
                    target.close()
        self.connection.executescript(SCHEMA)
        with self.transaction() as db:
            current = db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
            if current and int(current[0]) > 3:
                raise RuntimeError('database schema is newer than this relay supports')
            if 'display_path' not in {r['name'] for r in db.execute('PRAGMA table_info(claims)')}:
                db.execute('ALTER TABLE claims ADD COLUMN display_path TEXT')
            if current and int(current[0]) == 3:
                return
            if current and int(current[0]) == 2:
                self._room_sequences(db)
                self._web_tables(db)
                return
            for table in ('threads', 'messages', 'tasks', 'claims'):
                if 'room_id' not in {r['name'] for r in db.execute(f'PRAGMA table_info({table})')}:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN room_id TEXT NOT NULL DEFAULT 'default'")
            for column, definition in [('source', "TEXT NOT NULL DEFAULT 'agent'"),
                                       ('bytes', 'INTEGER NOT NULL DEFAULT 0'), ('thread_no', 'INTEGER')]:
                if column not in {r['name'] for r in db.execute('PRAGMA table_info(messages)')}:
                    db.execute(f'ALTER TABLE messages ADD COLUMN {column} {definition}')
            for statement in ROOM_SCHEMA.split(';'):
                if statement.strip():
                    db.execute(statement)
            db.execute("INSERT OR IGNORE INTO rooms VALUES ('default','default','open',?,'migration')", (time.time(),))
            db.execute("INSERT OR IGNORE INTO room_members(room_id,name,role,token_hash,active) "
                       "SELECT 'default',name,role,token_hash,active FROM agents WHERE role!='admin'")
            db.execute("INSERT OR IGNORE INTO room_threads(room_id,label,storage_key,creator,created,used,legacy_a,legacy_b) "
                       "SELECT 'default',id,id,creator,created,used,participant_a,participant_b FROM threads")
            db.execute("UPDATE messages SET bytes=length(CAST(text AS BLOB)),thread_no="
                       "(SELECT number FROM room_threads WHERE room_id='default' AND label=messages.thread)")
            db.execute("INSERT OR IGNORE INTO deliveries SELECT 'default',id,sender FROM messages")
            db.execute("INSERT OR IGNORE INTO deliveries SELECT 'default',id,recipient FROM messages")
            self._room_sequences(db)
            self._web_tables(db)

    @staticmethod
    def _web_tables(db):
        for statement in WEB_SCHEMA.split(';'):
            if statement.strip():
                db.execute(statement)
        db.execute("INSERT OR IGNORE INTO settings VALUES ('web_csrf_key',?)",(secrets.token_hex(32),))
        db.execute("INSERT OR REPLACE INTO settings VALUES ('schema_version','3')")

    @staticmethod
    def _room_sequences(db):
        """Expose room-local cursors while retaining global internal foreign keys.

        This also upgrades pre-release v2 databases atomically. Default-room v1
        cursors keep their original values; other rooms start at one.
        """
        done = db.execute("SELECT value FROM settings WHERE key='room_local_sequences'").fetchone()
        if done and done[0]=='1':
            return
        for table,column in [('messages','public_id'),('room_threads','public_number')]:
            if column not in {r['name'] for r in db.execute(f'PRAGMA table_info({table})')}:
                db.execute(f'ALTER TABLE {table} ADD COLUMN {column} INTEGER')
        last = {}
        for row in db.execute('SELECT id,room_id,public_id FROM messages ORDER BY room_id,id').fetchall():
            room = row['room_id']
            value = row['public_id']
            if value is None:
                value = row['id'] if room=='default' else last.get(room,0)+1
                db.execute('UPDATE messages SET public_id=? WHERE id=?',(value,row['id']))
            last[room] = max(last.get(room,0),value)
        last = {}
        for row in db.execute('SELECT number,room_id,public_number FROM room_threads ORDER BY room_id,number').fetchall():
            room = row['room_id']
            value = row['public_number']
            if value is None:
                value = last.get(room,0)+1
                db.execute('UPDATE room_threads SET public_number=? WHERE number=?',(value,row['number']))
            last[room] = max(last.get(room,0),value)
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS public_message_cursor ON messages(room_id,public_id)')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS public_thread_number ON room_threads(room_id,public_number)')
        db.execute("INSERT OR REPLACE INTO settings VALUES ('room_local_sequences','1')")

    @contextmanager
    def transaction(self, *, read_only=False):
        with self.lock:
            self.connection.execute('BEGIN' if read_only else 'BEGIN IMMEDIATE')
            try:
                yield self.connection
                self.connection.execute('COMMIT')
            except BaseException:
                self.connection.execute('ROLLBACK')
                raise

    def close(self):
        with self.lock:
            self.connection.close()
