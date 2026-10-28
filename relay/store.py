"""SQLite persistence. All domain read/check/write operations share a transaction."""
from contextlib import contextmanager
import sqlite3
import threading


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
    PRIMARY KEY(task_id, path)
);
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
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.connection.execute('BEGIN IMMEDIATE')
            try:
                yield self.connection
                self.connection.execute('COMMIT')
            except BaseException:
                self.connection.execute('ROLLBACK')
                raise

    def close(self):
        with self.lock:
            self.connection.close()
