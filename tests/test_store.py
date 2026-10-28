import tempfile
import unittest
from pathlib import Path
from relay.store import Store


class StoreTests(unittest.TestCase):
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
