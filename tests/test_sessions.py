from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from relay.domain import Domain, DomainError
from relay.store import Store


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'web.db'
        self.store = Store(self.path)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda:self.store.close())
        self.d = Domain(self.store)
        self.tokens = {name:self.d.mint_agent(name,role) for name,role in [('root','admin'),('other','admin'),('agent','agent'),('observer','observer')]}
        self.base = 1000000.0
        self.clock = patch('relay.domain.time.time',return_value=self.base)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def login(self,name='root',peer='127.0.0.1'):
        return self.d.session_create(self.digest(self.tokens[name]),peer)

    def error(self,code,fn,*args,**kwargs):
        with self.assertRaises(DomainError) as caught:
            fn(*args,**kwargs)
        self.assertEqual(caught.exception.code,code,str(caught.exception))
        return caught.exception

    def test_hashes_only_and_stable_csrf_after_restart(self):
        created = self.login()
        self.assertEqual(len(created['session']),43)
        self.assertEqual(len(created['csrf']),64)
        with self.store.transaction(read_only=True) as db:
            row = dict(db.execute('SELECT * FROM sessions').fetchone())
        self.assertEqual(row['session_hash'],self.digest(created['session']))
        self.assertEqual(row['credential_hash'],self.digest(self.tokens['root']))
        self.assertNotIn(created['session'],str(row))
        self.assertNotIn(created['csrf'],str(row))
        self.assertNotIn(self.tokens['root'],str(row))
        self.assertNotIn('127.0.0.1',str(row))
        self.store.close()
        self.store = Store(self.path)
        self.d = Domain(self.store)
        validated = self.d.session_validate(created['session'])
        self.assertEqual(validated['csrf'],created['csrf'])
        self.assertEqual(validated['expires_at'],created['expires_at'])
        self.assertEqual(validated['principal'],{'name':'root','role':'admin','room':None,'generation':1})

    def test_idle_expiry_at_exact_boundary(self):
        created = self.login()
        with patch('relay.domain.time.time',return_value=self.base+1800):
            self.assertIsNone(self.d.session_validate(created['session']))

    def test_absolute_expiry_never_slides_with_activity(self):
        created = self.login()
        for elapsed in range(1200,28800,1200):
            with patch('relay.domain.time.time',return_value=self.base+elapsed):
                current = self.d.session_validate(created['session'])
                self.assertEqual(current['expires_at'],self.base+28800)
        with patch('relay.domain.time.time',return_value=self.base+28799):
            self.assertIsNotNone(self.d.session_validate(created['session']))
        with patch('relay.domain.time.time',return_value=self.base+28800):
            self.assertIsNone(self.d.session_validate(created['session']))

    def test_bad_csrf_does_not_touch_idle_time(self):
        created = self.login()
        with patch('relay.domain.time.time',return_value=self.base+59):
            self.d.session_validate(created['session'])
        for csrf in (None,'0'*64,'☃',[],created['csrf']+'x'):
            with patch('relay.domain.time.time',return_value=self.base+61):
                self.error(403,self.d.session_validate,created['session'],csrf,True)
        with self.store.transaction(read_only=True) as db:
            self.assertEqual(db.execute('SELECT last_seen FROM sessions').fetchone()[0],self.base)
        with patch('relay.domain.time.time',return_value=self.base+61):
            self.d.session_validate(created['session'],created['csrf'],True)
        with self.store.transaction(read_only=True) as db:
            self.assertEqual(db.execute('SELECT last_seen FROM sessions').fetchone()[0],self.base+61)

    def test_admin_revoke_and_rotation_invalidate_sessions(self):
        created = self.login()
        replacement = self.digest('replacement-fixture-credential')
        with self.store.transaction() as db:
            db.execute("UPDATE agents SET token_hash=? WHERE name='root'",(replacement,))
        self.assertIsNone(self.d.session_validate(created['session']))
        newer = self.d.session_create(replacement,'127.0.0.1')
        self.d.revoke('root')
        self.assertIsNone(self.d.session_validate(newer['session']))

    def test_non_admin_credentials_rejected_and_failures_commit(self):
        for name in ('agent','observer'):
            self.error(401,self.login,name)
        invalid = self.digest('wrong-secret-fixture')
        self.error(401,self.d.session_create,invalid,'127.0.0.1')
        self.store.close()
        self.store = Store(self.path)
        self.d = Domain(self.store)
        with self.store.transaction(read_only=True) as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM login_attempts')]
        self.assertEqual(len(rows),3)
        self.assertNotIn(invalid,str(rows))
        self.assertNotIn('127.0.0.1',str(rows))

    def test_peer_throttle_persists_and_retry_window_expires(self):
        for _ in range(5):
            self.error(401,self.d.session_create,'0'*64,'127.0.0.1')
        self.store.close()
        self.store = Store(self.path)
        self.d = Domain(self.store)
        err = self.error(429,self.login)
        self.assertEqual(err.retry_after,900)
        self.assertIsNotNone(self.login(peer='127.0.0.2'))
        with patch('relay.domain.time.time',return_value=self.base+900):
            self.assertIn('session',self.login())

    def test_global_throttle_is_shared_across_peers(self):
        for i in range(30):
            self.error(401,self.d.session_create,'0'*64,'peer-'+str(i))
        err = self.error(429,self.login,peer='new-peer')
        self.assertEqual(err.retry_after,3600)
        with patch('relay.domain.time.time',return_value=self.base+3600):
            self.assertIn('session',self.login())

    def test_failure_threshold_is_atomic(self):
        def attempt(_):
            try:
                self.d.session_create('0'*64,'one-peer')
            except DomainError as err:
                return err.code
        with ThreadPoolExecutor(8) as pool:
            outcomes = list(pool.map(attempt,range(12)))
        self.assertEqual(outcomes.count(401),5)
        self.assertEqual(outcomes.count(429),7)
        with self.store.transaction(read_only=True) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM login_attempts').fetchone()[0],5)

    def test_logout_all_only_revokes_own_admin(self):
        one,two,other = self.login(),self.login(),self.login('other')
        self.assertEqual(self.d.session_revoke_all(one['session']),2)
        self.assertIsNone(self.d.session_validate(one['session']))
        self.assertIsNone(self.d.session_validate(two['session']))
        self.assertIsNotNone(self.d.session_validate(other['session']))
        self.error(401,self.d.session_revoke_all,one['session'])
        self.assertEqual(self.d.session_revoke(other['session']),1)
        self.assertEqual(self.d.session_revoke('bad'),0)

    def test_purge_removes_expired_stale_sessions_and_old_failures(self):
        self.login()
        self.error(401,self.d.session_create,'0'*64,'one-peer')
        with patch('relay.domain.time.time',return_value=self.base+3601):
            self.assertEqual(self.d.session_purge(),{'sessions':1,'attempts':1})

    def test_invalid_session_shapes_fail_closed(self):
        for value in (None,1,[],{},'','☃','x'*42,'x'*44,'x'*43):
            self.assertIsNone(self.d.session_validate(value))
