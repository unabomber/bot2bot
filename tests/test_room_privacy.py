"""Capability boundaries and metadata projections must not disclose content."""
import hashlib
import unittest
from relay.domain import Domain, DomainError
from relay.store import Store


class RoomPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.addCleanup(self.store.close)
        self.d = Domain(self.store)
        self.admin = self.lookup(self.d.mint_agent('root','admin'))
        self.people = {}
        for room in ('one','two'):
            created = self.d.create_room(self.admin,room,['a','b',{'name':'monitor','role':'monitor'}])
            for m in created['members']:
                self.people[room,m['name']] = self.lookup(m['token'])
        self.a = self.people['one','a']
        self.monitor = self.people['one','monitor']
        self.message = self.d.room_post(self.a,'one',['b'],'SECRET_THREAD','SECRET_TEXT')
        self.task = self.d.room_task_create(self.a,'one','SECRET_TITLE',['SECRET_FILE.py'])
        self.d.room_task_finish(self.a,'one',self.task['id'],'a/SECRET_BRANCH')

    def lookup(self, token):
        return self.d.lookup(hashlib.sha256(token.encode()).hexdigest())

    def denied(self, fn, *args):
        with self.assertRaises(DomainError) as err:
            fn(*args)
        self.assertEqual(err.exception.code,403)
        self.assertNotIn('SECRET',err.exception.message)

    def test_monitor_projection_never_selects_content(self):
        trace = []
        self.store.connection.set_trace_callback(trace.append)
        try:
            rows = self.d.monitor(self.monitor,'one')
            stats = self.d.stats(self.monitor,'one')
            members = self.d.members(self.monitor,'one')
        finally:
            self.store.connection.set_trace_callback(None)
        expected = {'id','ts','from','room','bytes','source','thread_no','to_count'}
        self.assertEqual(set(rows[0]),expected)
        self.assertEqual(rows[0]['bytes'],len('SECRET_TEXT'.encode()))
        self.assertEqual(rows[0]['to_count'],1)
        self.assertIsInstance(rows[0]['thread_no'],int)
        self.assertNotIn('SECRET',str(rows)+str(stats)+str(members))
        for sql in trace:
            self.assertNotIn('m.*',sql.lower())
            self.assertNotIn('m.text',sql.lower())
            self.assertNotIn('t.label',sql.lower())
            self.assertNotIn('token_hash',sql.lower())

    def test_monitor_denied_content_and_writes_at_domain_boundary(self):
        self.denied(self.d.room_fetch,self.monitor,'one')
        self.denied(self.d.room_tasks,self.monitor,'one')
        self.denied(self.d.room_post,self.monitor,'one',['b'],'topic','x')
        self.denied(self.d.room_task_create,self.monitor,'one','title',['x.py'])
        self.denied(self.d.inject,self.monitor,'one',['b'],'topic','x')
        self.denied(self.d.fetch,self.monitor)
        self.denied(self.d.list_rooms,self.monitor)

    def test_room_scoping_on_every_read_and_write_surface(self):
        self.denied(self.d.room_fetch,self.a,'two')
        self.denied(self.d.room_post,self.a,'two',['b'],'topic','x')
        self.denied(self.d.room_tasks,self.a,'two')
        self.denied(self.d.room_task_create,self.a,'two','title',['x.py'])
        self.denied(self.d.heartbeat,self.a,'two')
        self.denied(self.d.room_state,self.a,'two')
        self.denied(self.d.monitor,self.monitor,'two')
        self.denied(self.d.members,self.monitor,'two')
        self.denied(self.d.stats,self.monitor,'two')
        self.denied(self.d.fetch,self.a)
        self.assertEqual(self.d.status()['messages'],0)

    def test_legacy_observer_never_reads_new_rooms(self):
        observer = self.lookup(self.d.mint_agent('observer','observer'))
        self.denied(self.d.room_fetch,observer,'one')
        self.assertEqual(self.d.fetch(observer),[])
        self.denied(self.d.room_state,observer,'one')

    def test_role_and_generation_forgery_is_rejected(self):
        forged = dict(self.monitor,role='agent')
        self.denied(self.d.room_fetch,forged,'one')
        for generation in (None,True,0,999):
            forged = dict(self.a,generation=generation)
            self.denied(self.d.room_fetch,forged,'one')
        self.denied(self.d.create_room,self.a,'forbidden')

    def test_metadata_does_not_include_other_rooms(self):
        self.d.room_post(self.people['two','a'],'two',['b'],'OTHER_SECRET','OTHER_SECRET')
        rows = self.d.monitor(self.monitor,'one')
        self.assertEqual([r['id'] for r in rows],[self.message['id']])
        self.assertEqual(self.d.stats(self.monitor,'one')['messages'],1)
