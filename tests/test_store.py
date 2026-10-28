import tempfile
import sqlite3
import unittest
from pathlib import Path
from relay.store import Store


class StoreTests(unittest.TestCase):
    def test_read_transaction_does_not_reserve_writer_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'relay.db'
            store = Store(path)
            other = sqlite3.connect(path, timeout=0)
            try:
                with store.transaction(read_only=True) as db:
                    db.execute('SELECT * FROM settings').fetchall()
                    other.execute("INSERT INTO settings VALUES ('concurrent','yes')")
                    other.commit()
            finally:
                other.close()
                store.close()

    def test_upgrade_preserves_old_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'relay.db'
            db = sqlite3.connect(path)
            db.execute('CREATE TABLE claims(task_id INTEGER, path TEXT, PRIMARY KEY(task_id,path))')
            db.execute("INSERT INTO claims VALUES (1,'old/path.py')")
            db.commit()
            db.close()
            store = Store(path)
            try:
                with store.transaction(read_only=True) as db:
                    self.assertEqual(db.execute('SELECT COALESCE(display_path,path) FROM claims').fetchone()[0], 'old/path.py')
            finally:
                store.close()

    def test_commit_rollback_and_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'relay.db'
            store = Store(path)
            with store.transaction() as db:
                self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
                db.execute("INSERT INTO settings VALUES ('committed','yes')")
            with self.assertRaises(RuntimeError):
                with store.transaction() as db:
                    db.execute("INSERT INTO settings VALUES ('rolled_back','no')")
                    raise RuntimeError('abort')
            store.close()
            store = Store(path)
            try:
                with store.transaction() as db:
                    self.assertEqual(db.execute("SELECT value FROM settings WHERE key='committed'").fetchone()[0], 'yes')
                    self.assertIsNone(db.execute("SELECT value FROM settings WHERE key='rolled_back'").fetchone())
            finally:
                store.close()
