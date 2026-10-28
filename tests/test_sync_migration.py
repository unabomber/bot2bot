"""WAL-aware v3 backup, atomic v4 upgrades and durable synchronization state."""
import hashlib
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from relay.domain import Domain
from relay.store import Store


class SyncMigrationTests(unittest.TestCase):
    def fixture(self, path):
        store = Store(path)
        d = Domain(store)
        token = d.mint_agent('root','admin')
        admin = d.lookup(hashlib.sha256(token.encode()).hexdigest())
        room = d.create_room(admin,'room',['a','b'])
        tokens = {m['name']:m['token'] for m in room['members']}
        principals = {name:d.lookup(hashlib.sha256(t.encode()).hexdigest()) for name,t in tokens.items()}
        d.room_post(principals['a'],'room',['b'],'private-label','private payload')
        with store.transaction() as db:
            for table in ('sync_statuses','sync_enrollments','sync_versions','sync_rooms'):
                db.execute('DROP TABLE '+table)
            db.execute("UPDATE settings SET value='3' WHERE key='schema_version'")
            key = db.execute("SELECT value FROM settings WHERE key='web_csrf_key'").fetchone()[0]
        return store,admin,tokens,key

    def test_v3_backup_preserves_wal_data_and_keys_upgrade_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'relay.db'
            original,admin,tokens,key = self.fixture(path)
            try:
                upgraded = Store(path)
                upgraded.close()
                backup = Path(str(path)+'.v3.bak')
                stamp = backup.read_bytes()
                with closing(sqlite3.connect(backup)) as db:
                    self.assertEqual(db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0],'3')
                    self.assertEqual(db.execute('SELECT text FROM messages').fetchone()[0],'private payload')
                reopened = Store(path)
                try:
                    with reopened.transaction(read_only=True) as db:
                        self.assertEqual(db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0],'4')
                        self.assertEqual(db.execute("SELECT value FROM settings WHERE key='web_csrf_key'").fetchone()[0],key)
                    self.assertEqual(Domain(reopened).sync_monitor(admin,'room')['version'],0)
                finally:
                    reopened.close()
                self.assertEqual(backup.read_bytes(),stamp)
            finally:
                original.close()

    def test_upgrade_failure_rolls_back_all_sync_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'relay.db'
            store,_,_,_ = self.fixture(path)
            with store.transaction() as db:
                db.execute("CREATE TRIGGER reject_v4 BEFORE INSERT ON settings WHEN NEW.key='schema_version' AND NEW.value='4' BEGIN SELECT RAISE(ABORT,'no upgrade'); END")
            store.close()
            with self.assertRaises(sqlite3.IntegrityError):
                Store(path)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0],'3')
                self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'sync_%'").fetchone()[0],0)

    def test_pending_round_generation_and_notice_backoff_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'relay.db'
            store,admin,tokens,_ = self.fixture(path)
            store.close()
            store = Store(path)
            d = Domain(store)
            p = {n:d.lookup(hashlib.sha256(t.encode()).hexdigest()) for n,t in tokens.items()}
            d.sync_propose(p['a'],'room',0,'SECRET_STATE',deadline_seconds=86400)
            d.sync_status(p['a'],'room',0,'b','SECRET_REASON')
            d.sync_status(p['b'],'room',0,'a','SECRET_REASON')
            self.assertEqual(d.stats(admin,'room')['messages'],2)
            store.close()
            store = Store(path)
            try:
                d = Domain(store)
                self.assertFalse(d.sync_scan('room')['notify'])
                self.assertEqual(d.sync_state(p['a'],'room')['round']['state'],'SECRET_STATE')
                self.assertEqual(d.sync_ack(p['b'],'room',1)['version'],1)
                self.assertEqual(d.stats(admin,'room')['messages'],2)
            finally:
                store.close()


if __name__=='__main__':
    unittest.main()
