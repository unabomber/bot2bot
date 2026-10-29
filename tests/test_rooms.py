"""Room state, durable delivery, budgets and presence regression tests."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import tempfile
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from relay.domain import Domain, DomainError
from relay.store import Store


class RoomTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name)/'rooms.db')
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.store.close)
        self.d = Domain(self.store)
        token = self.d.mint_agent('root','admin')
        self.admin = self.principal(token)
        self.tokens = {}
        for room in ('alpha','beta'):
            result = self.d.create_room(self.admin,room,['a','b','c',{'name':'watch','role':'monitor'}])
            for member in result['members']:
                self.tokens[room,member['name']] = member['token']

    def principal(self, token):
        return self.d.lookup(hashlib.sha256(token.encode()).hexdigest())

    def p(self, name, room='alpha'):
        return self.principal(self.tokens[room,name])

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(DomainError) as caught:
            fn(*args,**kwargs)
        self.assertEqual(caught.exception.code,code,str(caught.exception))

    def test_room_creation_is_atomic_and_tokens_are_once_only(self):
        self.error(409,self.d.create_room,self.admin,'partial',['x','x'])
        self.assertNotIn('partial',[r['name'] for r in self.d.list_rooms(self.admin)])
        self.error(400,self.d.create_room,self.admin,'default')
        self.error(400,self.d.mint_member,self.admin,'alpha','human')
        self.error(400,self.d.mint_member,self.admin,'alpha','reader','observer')
        serialized = str(self.d.list_rooms(self.admin))+str(self.d.members(self.admin,'alpha'))
        self.assertNotIn(self.tokens['alpha','a'],serialized)
        self.assertEqual(self.p('a')['room'],'alpha')
        self.assertEqual(self.p('a')['generation'],1)

    def test_selective_and_broadcast_delivery_snapshot(self):
        one = self.d.room_post(self.p('a'),'alpha',['b'],'topic','private')
        self.assertEqual(self.d.room_fetch(self.p('c'),'alpha'),[])
        self.assertEqual(self.d.room_fetch(self.p('b'),'alpha'),[one])
        allmsg = self.d.room_post(self.p('a'),'alpha','*','topic','broadcast')
        self.assertEqual(allmsg['to'],['b','c'])
        self.tokens['alpha','late'] = self.d.mint_member(self.admin,'alpha','late')
        self.assertEqual(self.d.room_fetch(self.p('late'),'alpha'),[])
        future = self.d.room_post(self.p('b'),'alpha','*','topic','future')
        self.assertEqual(self.d.room_fetch(self.p('late'),'alpha'),[future])
        self.assertEqual(future['source'],'agent')
        self.assertTrue(future['untrusted'])
        self.error(400,self.d.room_post,self.p('a'),'alpha',['a'],'t','self')
        self.error(400,self.d.room_post,self.p('a'),'alpha',['watch'],'t','monitor')
        self.error(400,self.d.room_post,self.p('a'),'alpha',['missing'],'t','unknown')

    def test_room_thread_and_message_budgets_are_scoped(self):
        self.d = Domain(self.store,hourly_messages=2,hourly_threads=1,thread_budget=2)
        self.d.room_post(self.p('a'),'alpha',['b'],'same','one')
        self.d.room_post(self.p('c'),'alpha',['a'],'same','many-party thread')
        self.error(409,self.d.room_post,self.p('b'),'alpha',['c'],'same','over budget')
        self.d.room_post(self.p('a','beta'),'beta',['b'],'same','independent room')
        self.error(429,self.d.room_post,self.p('a'),'alpha',['b'],'other','thread budget')
        self.d.reset_room_thread(self.admin,'alpha','same')
        self.d.room_post(self.p('a'),'alpha',['b'],'same','two')
        self.error(429,self.d.room_post,self.p('a'),'alpha',['b'],'same','hourly budget')

    def test_close_pause_and_inject(self):
        before = self.d.room_post(self.p('a'),'alpha',['b'],'x','before')
        self.d.set_room_closed(self.admin,'alpha',True)
        self.error(423,self.d.room_post,self.p('a'),'alpha',['b'],'x','blocked')
        self.assertEqual(self.d.room_fetch(self.p('b'),'alpha'),[before])
        self.assertEqual(self.d.room_state(self.p('b'),'alpha'),{'status':'closed'})
        self.d.pause()
        injected = self.d.inject(self.admin,'alpha',['b'],'human note','hello')
        self.assertEqual((injected['from'],injected['source']),('human','human'))
        self.assertEqual(self.d.room_fetch(self.p('c'),'alpha'),[])
        self.assertEqual(self.d.room_fetch(self.p('b'),'alpha',before['id']),[injected])
        self.error(403,self.d.inject,self.p('a'),'alpha','*','x','fake human')
        self.error(413,self.d.inject,self.admin,'alpha','*','x','é'*8193)
        self.d.resume()
        self.d.set_room_closed(self.admin,'alpha',False)
        self.d.room_post(self.p('a'),'alpha',['b'],'x','after')

    def test_presence_lookup_throttle_and_heartbeat(self):
        base = time.time()
        with patch('relay.domain.time.time',return_value=base):
            principal = self.p('a')
        with patch('relay.domain.time.time',return_value=base+5):
            self.p('a')
            row = next(m for m in self.d.members(self.admin,'alpha') if m['name']=='a')
            self.assertEqual(row['last_seen'],base)
        with patch('relay.domain.time.time',return_value=base+61):
            row = next(m for m in self.d.members(self.admin,'alpha') if m['name']=='a')
            self.assertFalse(row['active'])
            self.d.heartbeat(principal,'alpha')
            row = next(m for m in self.d.members(self.admin,'alpha') if m['name']=='a')
            self.assertTrue(row['active'])
            self.assertEqual(row['last_seen'],base+61)

    def test_rotation_removal_and_durable_generation(self):
        cached = self.p('a')
        new_token = self.d.rotate_member(self.admin,'alpha','a')
        self.assertIsNone(self.p('a'))
        self.error(403,self.d.room_fetch,cached,'alpha')
        renewed = self.principal(new_token)
        self.assertEqual(renewed['generation'],2)
        self.d.room_post(renewed,'alpha',['b'],'x','new credential')
        self.d.revoke_member(self.admin,'alpha','a')
        self.error(403,self.d.room_fetch,renewed,'alpha')
        self.assertIsNone(self.principal(new_token))
        self.error(409,self.d.mint_member,self.admin,'alpha','a')
        with self.store.transaction(read_only=True) as db:
            actions = [r[0] for r in db.execute("SELECT action FROM room_events WHERE room_id='alpha'")]
        self.assertIn('rotate',actions)
        self.assertIn('revoke',actions)

    def test_tasks_are_room_scoped_and_claims_atomic(self):
        task = self.d.room_task_create(self.p('a'),'alpha','secret title',['Relay/X.py'])
        other = self.d.room_task_create(self.p('a','beta'),'beta','other',['relay/x.py'])
        self.error(409,self.d.room_task_create,self.p('b'),'alpha','overlap',['relay'])
        self.error(404,self.d.room_task_finish,self.p('a','beta'),'beta',task['id'],'a/wrong-room')
        self.error(403,self.d.room_task_finish,self.p('b'),'alpha',task['id'],'b/wrong-owner')
        done = self.d.room_task_finish(self.p('a'),'alpha',task['id'],'a/topic')
        self.assertEqual(done['files'],['Relay/X.py'])
        self.error(409,self.d.room_task_finish,self.p('a'),'alpha',task['id'],'a/overwrite')
        self.d.room_task_release(self.p('a'),'alpha',task['id'])
        self.d.room_task_create(self.p('b'),'alpha','released',['relay'])
        self.assertEqual(self.d.room_tasks(self.p('a','beta'),'beta'),[other])
        self.assertEqual(self.d.tasks(),[])

    def test_concurrent_budget_and_claims(self):
        self.d = Domain(self.store,thread_budget=1)
        def send(name):
            try:
                self.d.room_post(self.p(name),'alpha',['c'],'race','one winner')
                return 200
            except DomainError as err:
                return err.code
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(send,['a','b'])),[200,409])
        self.assertEqual(self.d.stats(self.admin,'alpha')['messages'],1)

    def test_injection_hourly_budget_persists_across_instances(self):
        self.d = Domain(self.store,hourly_injections=1)
        self.d.inject(self.admin,'alpha','*','notice','one')
        another = Domain(self.store,hourly_injections=1)
        self.error(429,another.inject,self.admin,'beta','*','notice','two')

    def test_legacy_and_room_default_share_visibility_and_budget(self):
        a = self.d.mint_agent('legacy_a')
        b = self.d.mint_agent('legacy_b')
        self.d = Domain(self.store,thread_budget=2)
        self.d.post('legacy_a','legacy_b','legacy','one')
        self.d.room_post(self.principal(b),'default',['legacy_a'],'legacy','two')
        self.assertEqual(len(self.d.fetch(self.principal(a))),2)
        self.error(409,self.d.post,'legacy_a','legacy_b','legacy','blocked')
        self.d.reset_room_thread(self.admin,'default','legacy')
        self.d.post('legacy_a','legacy_b','legacy','reset')

    def test_legacy_reuses_a_room_thread_at_creation_limit(self):
        a = self.d.mint_agent('legacy_a')
        self.d.mint_agent('legacy_b')
        self.d = Domain(self.store,hourly_threads=1)
        self.d.room_post(self.principal(a),'default',['legacy_b'],'shared','room first')
        self.d.post('legacy_a','legacy_b','shared','legacy reuses existing thread')
        self.assertEqual(len(self.d.fetch(self.principal(a))),2)
