import tempfile
import sqlite3
import unittest
from pathlib import Path
from relay.store import Store
from relay.store import SCHEMA
from relay.domain import Domain
import hashlib


def legacy_database(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript(SCHEMA)
    for name,role in [('a','agent'),('b','agent'),('root','admin')]:
        digest = hashlib.sha256(('fixture-'+name).encode()).hexdigest()
        db.execute('INSERT INTO agents(name,role,token_hash) VALUES (?,?,?)',(name,role,digest))
    db.execute("INSERT INTO threads VALUES ('old-thread','a','b','a',100,1)")
    db.execute("INSERT INTO messages(id,sender,recipient,thread,text,created) VALUES (41,'a','b','old-thread','héllo',100)")
    db.execute("INSERT INTO tasks(id,owner,title) VALUES (9,'a','old task')")
    db.execute("INSERT INTO claims(task_id,path,display_path) VALUES (9,'relay/x.py','Relay/X.py')")
    db.execute("UPDATE settings SET value='1' WHERE key='paused'")
    db.commit()
    return db


class StoreTests(unittest.TestCase):
    def test_room_upgrade_backups_committed_wal_and_preserves_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'legacy.db'
            old = legacy_database(path)
            store = Store(path)
            try:
                backup = Path(str(path)+'.v1.bak')
                self.assertTrue(backup.exists())
                snapshot = sqlite3.connect(backup)
                try:
                    self.assertEqual(snapshot.execute('SELECT text FROM messages WHERE id=41').fetchone()[0],'héllo')
                    self.assertIsNone(snapshot.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone())
                    self.assertIsNone(snapshot.execute("SELECT name FROM sqlite_master WHERE name='rooms'").fetchone())
                finally:
                    snapshot.close()
                d = Domain(store)
                principal = d.lookup(hashlib.sha256(b'fixture-a').hexdigest())
                admin = d.lookup(hashlib.sha256(b'fixture-root').hexdigest())
                self.assertEqual(principal,{'name':'a','role':'agent'})
                msg = d.room_fetch(principal,'default')[0]
                self.assertEqual((msg['id'],msg['text'],msg['thread'],msg['to']),(41,'héllo','old-thread',['b']))
                self.assertTrue(d.is_paused())
                self.assertEqual(d.tasks()[0]['files'],['Relay/X.py'])
                self.assertEqual(d.tasks()[0]['id'],9)
                watch = d.mint_member(admin,'default','watch','monitor')
                metadata = d.monitor(d.lookup(hashlib.sha256(watch.encode()).hexdigest()),'default')[0]
                self.assertEqual(metadata['bytes'],len('héllo'.encode()))
                d.resume()
                self.assertGreater(d.post('b','a','old-thread','new')['id'],41)
                initial_backup = backup.read_bytes()
            finally:
                store.close()
                old.close()
            reopened = Store(path)
            try:
                self.assertEqual(len(Domain(reopened).room_fetch({'name':'a','role':'agent'},'default')),2)
                self.assertEqual(backup.read_bytes(),initial_backup)
                with reopened.transaction(read_only=True) as db:
                    self.assertEqual(db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0],'2')
                    self.assertEqual(db.execute('SELECT count(*) FROM deliveries').fetchone()[0],4)
            finally:
                reopened.close()

    def test_room_upgrade_rolls_back_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'legacy.db'
            db = legacy_database(path)
            db.execute("CREATE TRIGGER prevent_upgrade BEFORE INSERT ON settings WHEN NEW.key='schema_version' BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
            db.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                Store(path)
            try:
                self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='rooms'").fetchone())
                self.assertNotIn('room_id',{r[1] for r in db.execute('PRAGMA table_info(messages)')})
                self.assertEqual(db.execute('SELECT text FROM messages WHERE id=41').fetchone()[0],'héllo')
                self.assertTrue(Path(str(path)+'.v1.bak').exists())
                db.execute('DROP TRIGGER prevent_upgrade')
                db.commit()
                recovered = Store(path)
                recovered.close()
            finally:
                db.close()

    def test_newer_schema_refused_without_modifying_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'future.db'
            db = sqlite3.connect(path)
            db.executescript(SCHEMA)
            db.execute("INSERT INTO settings VALUES ('schema_version','99')")
            db.commit()
            db.close()
            with self.assertRaisesRegex(RuntimeError,'newer'):
                Store(path)
            db = sqlite3.connect(path)
            try:
                self.assertEqual(db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0],'99')
                self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='rooms'").fetchone())
                self.assertFalse(Path(str(path)+'.v1.bak').exists())
            finally:
                db.close()

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
