from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from relay.domain import Domain, DomainError
from relay.store import Store


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'relay.db'
        self.store = Store(self.path)
        self.d = Domain(self.store)
        self.tokens = {name: self.d.mint_agent(name, role) for name, role in
                       [('openai', 'agent'), ('claude', 'agent'), ('third', 'agent'),
                        ('watch', 'observer'), ('human', 'admin')]}

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def principal(self, name):
        return self.d.lookup(hashlib.sha256(self.tokens[name].encode()).hexdigest())

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(DomainError) as raised:
            fn(*args, **kwargs)
        self.assertEqual(raised.exception.code, code, str(raised.exception))

    def test_tokens_hashed_revocation_and_no_identity_reuse(self):
        self.assertEqual(self.principal('openai'), {'name': 'openai', 'role': 'agent'})
        self.assertIsNone(self.d.lookup(self.tokens['openai']))
        with self.store.transaction() as db:
            digest = db.execute("SELECT token_hash FROM agents WHERE name='openai'").fetchone()[0]
            self.assertEqual(digest, hashlib.sha256(self.tokens['openai'].encode()).hexdigest())
        principal = self.principal('openai')
        self.d.revoke('openai')
        self.assertIsNone(self.principal('openai'))
        self.error(403, self.d.fetch, principal)
        self.error(409, self.d.mint_agent, 'openai')
        self.error(403, self.d.post, 'openai', 'claude', 't', 'hello')

    def test_last_admin_cannot_be_revoked(self):
        self.error(409, self.d.revoke, 'human')
        self.assertIsNotNone(self.principal('human'))
        token = self.d.mint_agent('backup', 'admin')
        self.d.revoke('human')
        self.assertIsNone(self.principal('human'))
        self.error(409, self.d.revoke, 'backup')
        self.assertIsNotNone(self.d.lookup(hashlib.sha256(token.encode()).hexdigest()))

    def test_visibility_replay_and_monotonic_ids_after_restart(self):
        one = self.d.post('openai', 'claude', 't', 'first')
        two = self.d.post('claude', 'openai', 't', 'reply')
        three = self.d.post('third', 'claude', 'private', 'other conversation')
        self.assertTrue(one['untrusted'])
        self.assertEqual([m['id'] for m in self.d.fetch(self.principal('openai'))], [one['id'], two['id']])
        self.assertEqual(len(self.d.fetch(self.principal('watch'))), 3)
        self.assertEqual(self.d.fetch(self.principal('openai'), two['id']), [])
        self.assertEqual(self.d.fetch(self.principal('claude'), one['id'], 1), [two])
        self.store.close()
        self.store = Store(self.path)
        self.d = Domain(self.store)
        self.assertEqual(self.d.fetch(self.principal('human')), [one, two, three])
        four = self.d.post('openai', 'claude', 't', 'after restart')
        self.assertGreater(four['id'], three['id'])

    def test_pair_validation_roles_and_inputs(self):
        self.d.post('openai', 'claude', 't', 'first')
        self.error(409, self.d.post, 'third', 'claude', 't', 'hijack')
        self.error(400, self.d.post, 'openai', 'openai', 'new', 'self')
        self.error(403, self.d.post, 'unknown', 'claude', 'new', 'unknown')
        self.error(400, self.d.post, 'openai', 'human', 'new', 'admin')
        self.error(403, self.d.post, 'watch', 'claude', 'new', 'observer write')
        self.error(400, self.d.post, 'openai', 'claude', 'new', '\ud800')
        self.error(400, self.d.post, 'openai', 'claude', '\ud800', 'text')
        self.error(400, self.d.create_task, 'openai', '\ud800', ['file.py'])
        self.error(413, self.d.post, 'openai', 'claude', 'new', 'é' * 8193)
        self.d.post('openai', 'claude', 'new', 'é' * 4096)
        for bad in [-1, True, '1', 2**64]:
            self.error(400, self.d.fetch, self.principal('openai'), bad)
        self.error(403, self.d.fetch, {'name': 'openai', 'role': 'admin'})
        self.error(403, self.d.fetch, {'name': 'openai', 'extra': 1})

    def test_budget_atomicity_persistence_and_reset(self):
        self.d = Domain(self.store, thread_budget=2, hourly_messages=3, hourly_threads=1)
        self.d.post('openai', 'claude', 't', '1')
        self.d.post('claude', 'openai', 't', '2')
        self.error(409, self.d.post, 'openai', 'claude', 't', '3')
        self.d.reset_thread('t')
        self.d.post('openai', 'claude', 't', '3')
        self.error(429, self.d.post, 'openai', 'claude', 'new', 'new thread')
        self.d.reset_thread('t')
        self.d.post('openai', 'claude', 't', '4')
        self.store.close()
        self.store = Store(self.path)
        self.d = Domain(self.store, thread_budget=2, hourly_messages=3, hourly_threads=1)
        self.error(429, self.d.post, 'openai', 'claude', 't', '5')
        with patch('relay.domain.time.time', return_value=__import__('time').time() + 3601):
            self.d.post('openai', 'claude', 'new', 'window expired')
        self.error(404, self.d.reset_thread, 'missing')

    def test_pause_persisted_reads_and_admin_recovery(self):
        self.d.post('openai', 'claude', 't', 'before pause')
        task = self.d.create_task('openai', 'task', ['relay/a.py'])
        self.d.pause()
        self.assertTrue(self.d.is_paused())
        self.error(423, self.d.post, 'openai', 'claude', 't', 'no')
        self.error(423, self.d.create_task, 'claude', 'task', ['b.py'])
        self.error(423, self.d.finish_task, 'openai', task['id'], 'openai/task')
        self.error(423, self.d.release_task, 'openai', task['id'])
        self.assertEqual(len(self.d.fetch(self.principal('watch'))), 1)
        self.d.mint_agent('new_agent')
        self.store.close()
        self.store = Store(self.path)
        self.d = Domain(self.store)
        self.assertTrue(self.d.is_paused())
        self.d.resume()
        self.d.post('openai', 'claude', 't', 'resumed')

    def test_claim_normalization_ownership_and_release(self):
        task = self.d.create_task('openai', 'storage', ['Relay\\Store.py'])
        self.assertEqual(task['files'], ['Relay/Store.py'])
        for owner in ['openai', 'claude']:
            self.error(409, self.d.create_task, owner, 'duplicate', ['relay/STORE.py'])
            self.error(409, self.d.create_task, owner, 'parent', ['relay'])
        self.error(403, self.d.finish_task, 'claude', task['id'], 'claude/wrong')
        self.error(400, self.d.finish_task, 'openai', task['id'], 'main')
        self.error(400, self.d.finish_task, 'openai', task['id'], 'openai/x..y')
        done = self.d.finish_task('openai', task['id'], 'openai/store')
        self.assertEqual(done['status'], 'done')
        self.error(409, self.d.finish_task, 'openai', task['id'], 'openai/overwrite')
        self.assertEqual(self.d.tasks()[0]['branch'], 'openai/store')
        self.error(409, self.d.create_task, 'claude', 'still held', ['relay'])
        self.d.release_task('openai', task['id'])
        self.d.create_task('claude', 'released', ['relay'])
        self.error(409, self.d.release_task, 'openai', task['id'])
        self.assertEqual(self.d.status()['owners']['claude']['file_share'], 1)
        for bad in ['/etc', '../x', 'a/../b', 'C:\\foo', 'a//b', '.', 'a./b', 'a\x00b']:
            self.error(400, self.d.create_task, 'openai', 'bad path', [bad])
        self.error(409, self.d.create_task, 'openai', 'nested', ['x', 'x/y'])
        self.assertEqual(len(self.d.tasks()), 2)

    def test_concurrent_claim_and_budget_checks(self):
        def claim(owner):
            try:
                self.d.create_task(owner, 'race', ['same.py'])
                return 200
            except DomainError as exc:
                return exc.code
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(claim, ['openai', 'claude'])), [200, 409])
        self.d = Domain(self.store, thread_budget=1)
        def send(sender):
            try:
                self.d.post(sender, 'claude' if sender == 'openai' else 'openai', 'race', 'hello')
                return 200
            except DomainError as exc:
                return exc.code
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(send, ['openai', 'claude'])), [200, 409])
        self.assertEqual(self.d.status()['messages'], 1)
