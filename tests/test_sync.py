"""Agreement, drift, recovery and bounded durable stall notification rules."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import unittest
from unittest.mock import patch

from relay.domain import Domain, DomainError
from relay.store import Store


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.clock = patch('relay.domain.time.time', side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.store = Store(':memory:')
        self.addCleanup(self.store.close)
        self.d = Domain(self.store)
        token = self.d.mint_agent('root','admin')
        self.admin = self.principal(token)
        self.tokens = {}
        self.ps = {}
        for room in ('alpha','beta'):
            result = self.d.create_room(self.admin,room,['a','b','c',{'name':'watch','role':'monitor'}])
            for m in result['members']:
                self.tokens[room,m['name']] = m['token']
                self.ps[room,m['name']] = self.principal(m['token'])

    def principal(self, token):
        return self.d.lookup(hashlib.sha256(token.encode()).hexdigest())

    def p(self, name, room='alpha'):
        return self.ps[room,name]

    def error(self, code, fn, *args, **kw):
        with self.assertRaises(DomainError) as caught:
            fn(*args,**kw)
        self.assertEqual(caught.exception.code,code,str(caught.exception))

    def propose(self, text='PRIVATE_STATE', **kw):
        return self.d.sync_propose(self.p('a'),'alpha',self.d.sync_state(self.p('a'),'alpha')['version'],text,**kw)

    def agree(self, version):
        self.d.sync_ack(self.p('b'),'alpha',version)
        return self.d.sync_ack(self.p('c'),'alpha',version)

    def test_commit_requires_exact_explicit_quorum(self):
        initial = self.d.sync_state(self.p('a'),'alpha')
        self.assertEqual((initial['version'],initial['state']),(0,''))
        self.assertEqual(initial['drift'],[])
        one = self.propose()
        self.assertEqual(one['round']['version'],1)
        self.assertEqual(one['unacked'],['b','c'])
        self.d.sync_ack(self.p('b'),'alpha',1)
        self.assertEqual(self.d.sync_state(self.p('a'),'alpha')['version'],0)
        final = self.d.sync_ack(self.p('c'),'alpha',1)
        self.assertEqual((final['version'],final['state'],final['round']),(1,'PRIVATE_STATE',None))
        self.assertEqual(final['drift'],[])
        self.error(409,self.d.sync_ack,self.p('b'),'alpha',1)

    def test_abort_never_reuses_version_or_delayed_ack(self):
        self.propose('first')
        self.d.sync_nack(self.p('b'),'alpha',1,'disagree')
        second = self.propose('different')
        self.assertEqual(second['round']['version'],2)
        self.error(409,self.d.sync_ack,self.p('c'),'alpha',1)
        self.assertEqual(self.agree(2)['version'],2)
        self.error(409,self.d.sync_propose,self.p('a'),'alpha',1,'stale')

    def test_concurrent_proposals_have_one_winner(self):
        def attempt(name):
            try:
                return self.d.sync_propose(self.p(name),'alpha',0,name)['round']['version']
            except DomainError as e:
                return e.code
        with ThreadPoolExecutor(2) as pool:
            values = list(pool.map(attempt,['a','b']))
        self.assertEqual(sorted(values),[1,409])

    def test_single_enrollee_commit_and_validation(self):
        self.error(400,self.propose,enrolled=['b'])
        self.error(400,self.propose,enrolled=['a','a'])
        self.error(400,self.propose,enrolled=['a','watch'])
        self.error(400,self.propose,enrolled=[])
        self.error(400,self.propose,enrolled=['a',{}])
        self.error(400,self.propose,text='é'*2049)
        self.error(400,self.propose,text='\ud800')
        self.error(400,self.propose,deadline_seconds=True)
        self.assertEqual(self.propose(enrolled=['a'])['version'],1)

    def test_rotation_invalidates_old_ack_without_shrinking_quorum(self):
        self.propose()
        self.d.sync_ack(self.p('b'),'alpha',1)
        fresh = self.d.rotate_member(self.admin,'alpha','b')
        # rotate_member returns a token dictionary.
        token = fresh['token'] if isinstance(fresh,dict) else fresh
        new_b = self.principal(token)
        self.d.sync_ack(self.p('c'),'alpha',1)
        self.assertEqual(self.d.sync_state(self.p('a'),'alpha')['version'],0)
        self.assertEqual(self.d.sync_state(self.p('a'),'alpha')['unacked'],['b'])
        self.error(403,self.d.sync_ack,new_b,'alpha',1)
        self.error(403,self.d.sync_ack,self.p('b'),'alpha',1)

    def test_revoke_and_late_join_do_not_change_enrollment(self):
        self.propose()
        self.d.mint_member(self.admin,'alpha','late')
        self.d.revoke_member(self.admin,'alpha','b')
        self.d.sync_ack(self.p('c'),'alpha',1)
        state = self.d.sync_state(self.p('a'),'alpha')
        self.assertEqual(state['round']['enrolled'],['a','b','c'])
        self.assertEqual(state['version'],0)

    def test_admin_remove_creates_new_round_with_fresh_votes(self):
        self.propose()
        next_round = self.d.sync_remove(self.admin,'alpha','a')
        self.assertEqual(next_round['round']['version'],2)
        self.assertEqual(next_round['unacked'],['b','c'])
        self.error(409,self.d.sync_ack,self.p('b'),'alpha',1)
        self.d.sync_ack(self.p('b'),'alpha',2)
        self.assertEqual(self.d.sync_ack(self.p('c'),'alpha',2)['version'],2)
        self.assertEqual(self.d.room_state(self.p('a'),'alpha')['status'],'open')
        self.assertTrue(self.principal(self.tokens['alpha','a']))  # quorum removal does not revoke credentials

    def test_reset_requires_fresh_agreement_and_cannot_rewind(self):
        self.propose('old')
        self.agree(1)
        reset = self.d.sync_reset(self.admin,'alpha',0)
        self.assertEqual((reset['version'],reset['round']['version']),(1,2))
        self.d.sync_ack(self.p('a'),'alpha',2)
        self.d.sync_ack(self.p('b'),'alpha',2)
        final = self.d.sync_ack(self.p('c'),'alpha',2)
        self.assertEqual((final['version'],final['state']),(2,''))

    def test_deadline_abort_is_persisted_even_when_late_vote_rejected(self):
        self.propose(deadline_seconds=5)
        self.now += 5
        self.error(409,self.d.sync_ack,self.p('b'),'alpha',1)
        state = self.d.sync_state(self.p('a'),'alpha')
        self.assertIsNone(state['round'])
        self.assertEqual(state['kind'],'silent')
        self.assertEqual(self.d.stats(self.admin,'alpha')['messages'],1)
        self.assertFalse(self.d.sync_scan('alpha',self.now)['notify'])
        self.assertEqual(self.propose()['round']['version'],2)

    def test_state_and_reasons_never_leak_to_monitor(self):
        self.propose('PRIVATE_STATE')
        self.d.sync_status(self.p('a'),'alpha',0,'b','PRIVATE_REASON')
        monitor = self.d.sync_monitor(self.p('watch'),'alpha')
        serialized = json.dumps(monitor)+json.dumps(self.d.monitor(self.p('watch'),'alpha'))
        self.assertNotIn('PRIVATE_STATE',serialized)
        self.assertNotIn('PRIVATE_REASON',serialized)
        self.assertNotIn('state',monitor)
        self.error(403,self.d.sync_state,self.p('watch'),'alpha')
        self.error(403,self.d.sync_state,self.p('a','beta'),'alpha')
        self.error(403,self.d.sync_monitor,self.p('a'),'alpha')
        self.error(403,self.d.sync_propose,self.admin,'alpha',0,'admin proposal')

    def test_stale_declared_version_is_visible_drift(self):
        self.propose()
        self.agree(1)
        self.now += 1
        self.d.sync_status(self.p('b'),'alpha',0,None,'catching up')
        self.assertIn('b',self.d.sync_monitor(self.p('watch'),'alpha')['drift'])
        self.error(409,self.d.sync_status,self.p('b'),'alpha',99,None,'future')
        self.error(400,self.d.sync_status,self.p('b'),'alpha',1,'b','self')

    def test_strict_mode_is_enforced_atomically_on_say_only(self):
        self.propose()
        self.agree(1)
        self.d.set_room_sync(self.admin,'alpha',strict=True)
        self.error(409,self.d.room_post,self.p('a'),'alpha',['b'],'t','stale',state_version=0)
        self.error(409,self.d.room_post,self.p('a'),'alpha',['b'],'t','missing')
        self.error(409,self.d.room_post,self.p('a'),'alpha',['b'],'t','bool',state_version=True)
        self.d.room_post(self.p('a'),'alpha',['b'],'t','current',state_version=1)
        self.d.inject(self.admin,'alpha',['b'],'t','human recovery')
        self.assertEqual(len(self.d.room_fetch(self.p('b'),'alpha')),2)

    def test_cycle_notice_is_atomic_idempotent_and_backed_off(self):
        self.d.sync_status(self.p('a'),'alpha',0,'b','private a')
        self.d.sync_status(self.p('b'),'alpha',0,'a','private b')
        self.assertEqual(len(self.d.room_fetch(self.p('a'),'alpha')),0)     # a fresh cycle gets a grace period first
        with ThreadPoolExecutor(4) as pool:
            scans = list(pool.map(lambda _: self.d.sync_scan('alpha',self.now),range(4)))
        self.assertFalse(any(r['notify'] for r in scans))
        self.now += 60
        with ThreadPoolExecutor(4) as pool:
            scans = list(pool.map(lambda _: self.d.sync_scan('alpha',self.now),range(4)))
        self.assertEqual(sum(1 for r in scans if r['notify']),1)           # concurrent scans announce exactly once
        rows = self.d.room_fetch(self.p('a'),'alpha')
        self.assertEqual((rows[0]['from'],rows[0]['source'],rows[0]['level']),('relay','system','warn'))
        self.assertNotIn('private',rows[0]['text'])
        self.assertFalse(self.d.sync_scan('alpha',self.now)['notify'])
        for delta in (120,240,480,960):
            self.now += delta
            self.assertTrue(self.d.sync_scan('alpha',self.now)['notify'])
        self.now += 2000
        self.assertFalse(self.d.sync_scan('alpha',self.now)['notify'])
        self.assertEqual(len(self.d.room_fetch(self.p('a'),'alpha')),5)

    def test_waiting_does_not_repeat_reset_clock_and_recovers(self):
        self.d.set_room_sync(self.admin,'alpha',stall_seconds=5)
        for n in ('a','b','c'):
            self.d.sync_status(self.p(n),'alpha',0,'human','waiting')
        self.now += 4
        self.d.sync_status(self.p('a'),'alpha',0,'human','still waiting')
        self.assertFalse(self.d.sync_scan('alpha',self.now)['stalled'])
        self.now += 1
        self.assertEqual(self.d.sync_scan('alpha',self.now)['kind'],'all_waiting')
        self.d.sync_status(self.p('b'),'alpha',0,None,'working')
        self.assertFalse(self.d.sync_scan('alpha',self.now)['stalled'])

    def test_actual_open_waits_use_traffic_clock_and_finally_cleanup(self):
        self.d.set_room_sync(self.admin,'alpha',stall_seconds=5)
        for n in ('a','b','c'):
            self.d.sync_wait(self.p(n),'alpha',True)
        self.now += 4
        self.d.room_post(self.p('a'),'alpha',['b'],'t','progress')
        self.now += 2
        self.assertFalse(self.d.sync_scan('alpha',self.now)['stalled'])
        self.now += 3
        self.assertEqual(self.d.sync_scan('alpha',self.now)['kind'],'all_waiting')
        self.d.sync_wait(self.p('a'),'alpha',False)
        self.assertFalse(self.d.sync_scan('alpha',self.now)['stalled'])

    def test_autopass_is_opt_in_and_never_changes_agreed_document(self):
        self.d.set_room_sync(self.admin,'alpha',turn='a',stall_seconds=5)
        self.d.sync_status(self.p('a'),'alpha',0,'b','wait')
        self.d.sync_status(self.p('b'),'alpha',0,'a','wait')
        self.now += 60
        self.d.sync_scan('alpha',self.now)
        self.assertEqual(self.d.sync_monitor(self.admin,'alpha')['turn'],'a')
        self.d.set_room_sync(self.admin,'alpha',auto_pass=True)
        self.now += 120
        self.d.sync_scan('alpha',self.now)
        state = self.d.sync_state(self.p('a'),'alpha')
        self.assertEqual((state['turn'],state['version'],state['state']),('b',0,''))
        self.assertEqual(state['turn_version'],2)

    def test_system_sender_and_thread_reserved_and_hourly_budget(self):
        self.error(400,self.d.mint_member,self.admin,'alpha','ReLaY')
        self.error(400,self.d.mint_agent,'relay','admin')
        self.error(400,self.d.room_post,self.p('a'),'alpha',['b'],'__relay_sync__','spoof')
        for _ in range(20):
            self.assertIsNotNone(self.d.system_notice('alpha','*','notice'))
        self.assertIsNone(self.d.system_notice('alpha','*','capped'))
        self.assertEqual(self.d.stats(self.admin,'alpha')['messages'],20)
        self.now += 3600
        self.assertIsNotNone(self.d.system_notice('alpha','*','new hour'))

    def test_legacy_default_say_cannot_bypass_strict_mode(self):
        a,b = self.d.mint_agent('legacy-a'),self.d.mint_agent('legacy-b')
        self.d.set_room_sync(self.admin,'default',strict=True)
        self.error(409,self.d.post,'legacy-a','legacy-b','t','missing')
        self.d.post('legacy-a','legacy-b','t','current',state_version=0)

    def test_enabled_inventory_closed_room_and_revoked_wait_cleanup(self):
        self.assertEqual(self.d.sync_enabled_rooms(),[])
        self.d.set_room_sync(self.admin,'alpha',strict=True)
        self.assertEqual(self.d.sync_enabled_rooms(),['alpha'])
        self.d.sync_wait(self.p('a'),'alpha',True)
        self.d.revoke_member(self.admin,'alpha','a')
        self.d.sync_wait(self.p('a'),'alpha',False)
        self.assertEqual(self.d._sync_waits,{})
        self.d.set_room_closed(self.admin,'alpha',True)
        self.assertEqual(self.d.sync_enabled_rooms(),[])

    def test_new_members_and_new_credential_generations_must_resync(self):
        self.propose()
        self.agree(1)
        token = self.d.mint_member(self.admin,'alpha','late')
        fresh = self.d.rotate_member(self.admin,'alpha','b')
        view = self.d.sync_monitor(self.admin,'alpha')
        self.assertEqual(view['drift'],['b','late'])
        self.assertIsNone(view['acks']['b'])
        self.assertIsNone(view['acks']['late'])
        self.d.sync_status(self.principal(fresh),'alpha',1,None,'resynced')
        self.d.sync_status(self.principal(token),'alpha',1,None,'resynced')
        self.assertEqual(self.d.sync_monitor(self.admin,'alpha')['drift'],[])

    def test_expired_round_names_rotated_previously_acked_participant(self):
        self.propose(deadline_seconds=5)
        self.d.sync_ack(self.p('b'),'alpha',1)
        self.d.rotate_member(self.admin,'alpha','b')
        self.d.sync_ack(self.p('c'),'alpha',1)
        self.now += 5
        result = self.d.sync_scan('alpha',self.now)
        self.assertEqual((result['kind'],result['members']),('silent',['b']))

    def test_long_wait_chain_reports_only_the_cycle_members(self):
        names = ['n'+str(i).zfill(4) for i in range(1000)]
        self.d.create_room(self.admin,'large',names[:100])
        for n in names[100:]:
            self.d.mint_member(self.admin,'large',n)
        self.d.set_room_sync(self.admin,'large',stall_seconds=5)
        with self.store.transaction() as db:
            db.executemany('INSERT INTO sync_statuses VALUES (?,?,?,?,?,?,?,?)',
                [('large',n,1,0,names[i+1] if i<999 else names[998],'private',self.now,None) for i,n in enumerate(names)])
        scan = self.d.sync_scan('large',self.now+5)     # grace for a 5 s stall time is 5 s
        self.assertEqual((scan['kind'],scan['members']),('cycle',names[-2:]))


if __name__=='__main__':
    unittest.main()
