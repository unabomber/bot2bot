"""Sync v2: wait lifecycle, incident backoff, commit-time drift, atomic respond, renew, resume, levels, budgets."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from relay.domain import Domain, DomainError
from relay.store import Store


class SyncV2Tests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.clock = patch('relay.domain.time.time', side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.store = Store(':memory:')
        self.addCleanup(self.store.close)
        self.d = Domain(self.store, thread_budget=10)
        self.admin = self.principal(self.d.mint_agent('root', 'admin'))
        self.ps = {}
        result = self.d.create_room(self.admin, 'alpha', ['a', 'b', 'c', {'name': 'watch', 'role': 'monitor'}])
        for m in result['members']:
            self.ps[m['name']] = self.principal(m['token'])

    def principal(self, token):
        return self.d.lookup(hashlib.sha256(token.encode()).hexdigest())

    def p(self, name):
        return self.ps[name]

    def error(self, code, fn, *args, **kw):
        with self.assertRaises(DomainError) as caught:
            fn(*args, **kw)
        self.assertEqual(caught.exception.code, code, str(caught.exception))

    def propose(self, who='a', text='S', **kw):
        version = self.d.sync_state(self.p(who), 'alpha')['version']
        return self.d.sync_propose(self.p(who), 'alpha', version, text, **kw)

    def agree(self, version, who=('b', 'c')):
        for name in who:
            self.d.sync_ack(self.p(name), 'alpha', version)

    def status(self, who, version, waiting_on):
        return self.d.sync_status(self.p(who), 'alpha', version, waiting_on, 'r')

    def system_rows(self, who='a'):
        return [m for m in self.d.room_fetch(self.p(who), 'alpha') if m['source'] == 'system']

    # ---- wait lifecycle ----
    def test_own_ack_clears_own_obsolete_wait_and_peer_waits_on_the_actor(self):
        self.propose()
        self.status('a', 0, 'b')            # a waits for b's ack
        self.status('b', 0, 'a')            # b (stale) says it waits for a: a cycle
        self.d.sync_ack(self.p('b'), 'alpha', 1)
        waits = self.d.sync_monitor(self.p('watch'), 'alpha')['waiting_on']
        self.assertIsNone(waits['b'])       # b acted, so its own wait ended
        self.assertIsNone(waits['a'])       # a was waiting for b's ack, which just happened

    def test_chat_does_not_satisfy_a_wait(self):
        self.status('a', 0, 'b')
        self.d.room_post(self.p('b'), 'alpha', ['a'], 'main', 'just chatting')
        self.assertEqual(self.d.sync_monitor(self.p('watch'), 'alpha')['waiting_on']['a'], 'b')

    def test_propose_and_nack_also_clear_waits(self):
        self.status('b', 0, 'a')
        self.propose('a')
        self.assertIsNone(self.d.sync_monitor(self.p('watch'), 'alpha')['waiting_on']['b'])   # b waited for a's proposal
        self.status('a', 0, 'c')
        self.d.sync_nack(self.p('b'), 'alpha', 1, 'wrong')
        self.assertIsNone(self.d.sync_monitor(self.p('watch'), 'alpha')['waiting_on'].get('b'))

    def test_chess_style_alternation_never_reports_a_false_cycle(self):
        for move in range(1, 7):
            mover, other = ('a', 'b') if move % 2 else ('b', 'a')
            version = self.d.sync_state(self.p(mover), 'alpha')['version']
            self.d.sync_propose(self.p(mover), 'alpha', version, f'move {move}', enrolled=['a', 'b'])
            self.status(mover, version, other)
            self.status(other, version, mover)              # the other side's earlier wait is stale
            self.d.sync_ack(self.p(other), 'alpha', version + 1)
            self.now += 40
            self.assertFalse(self.d.sync_scan('alpha', self.now)['stalled'], move)
        self.assertEqual(self.system_rows(), [])

    def test_cycle_waits_for_the_grace_period(self):
        self.status('a', 0, 'b')
        self.status('b', 0, 'a')
        self.assertFalse(self.d.sync_scan('alpha', self.now + 10)['stalled'])   # stall_seconds 60 -> grace 30
        self.assertTrue(self.d.sync_scan('alpha', self.now + 31)['stalled'])

    # ---- incident backoff ----
    def test_version_churn_does_not_restart_notice_backoff(self):
        self.status('a', 0, 'b')
        self.status('b', 0, 'a')
        self.now += 31
        self.assertTrue(self.d.sync_scan('alpha', self.now)['notify'])
        self.d.sync_propose(self.p('c'), 'alpha', 0, 'churn', enrolled=['a', 'b', 'c'])   # allocates a version
        self.now += 10
        self.assertFalse(self.d.sync_scan('alpha', self.now)['notify'])         # still the same incident, inside backoff
        self.assertEqual(len(self.system_rows()), 1)

    def test_incident_ends_when_the_cycle_really_resolves(self):
        self.status('a', 0, 'b')
        self.status('b', 0, 'a')
        self.now += 31
        self.d.sync_scan('alpha', self.now)
        self.status('b', 0, None)
        self.assertFalse(self.d.sync_scan('alpha', self.now)['stalled'])
        self.status('b', 0, 'a')                                               # a genuinely new cycle
        self.now += 31
        self.assertTrue(self.d.sync_scan('alpha', self.now)['notify'])

    def test_notice_levels_first_warn_repeat_info_expiry_critical(self):
        self.status('a', 0, 'b')
        self.status('b', 0, 'a')
        self.now += 31
        self.d.sync_scan('alpha', self.now)
        self.now += 120
        self.d.sync_scan('alpha', self.now)
        levels = [m['level'] for m in self.system_rows()]
        self.assertEqual(levels, ['warn', 'info'])
        self.status('a', 0, None)
        self.status('b', 0, None)
        self.propose(deadline_seconds=60)
        self.now += 61
        self.d.sync_scan('alpha', self.now)
        self.assertEqual(self.system_rows()[-1]['level'], 'critical')
        self.assertTrue(all('level' not in m for m in self.d.room_fetch(self.p('a'), 'alpha') if m['source'] != 'system'))

    # ---- drift ----
    def test_honest_pre_commit_status_is_not_drift(self):
        self.propose('a')                          # a implicitly acks version 1
        self.now += 1
        self.status('a', 0, 'b')                   # honest: committed is still 0 while waiting
        self.now += 1
        self.agree(1)                              # peers ack, version 1 commits
        self.assertNotIn('a', self.d.sync_monitor(self.p('watch'), 'alpha')['drift'])

    def test_stale_declaration_after_commit_is_still_drift(self):
        self.propose('a')
        self.agree(1)
        self.now += 1
        self.status('b', 0, None)
        self.assertIn('b', self.d.sync_monitor(self.p('watch'), 'alpha')['drift'])

    # ---- respond ----
    def test_respond_acks_and_proposes_atomically_and_is_idempotent(self):
        self.propose('a')
        self.d.sync_ack(self.p('c'), 'alpha', 1)
        result = self.d.sync_respond(self.p('b'), 'alpha', 1, 1, 'reply', 'p', None, 'k1')
        self.assertFalse(result['replayed'])
        view = self.d.sync_state(self.p('b'), 'alpha')
        self.assertEqual(view['version'], 1)
        self.assertEqual((view['round']['version'], view['round']['acked']), (2, ['b']))
        again = self.d.sync_respond(self.p('b'), 'alpha', 1, 1, 'reply', 'p', None, 'k1')
        self.assertTrue(again['replayed'])
        self.assertEqual(self.d.sync_state(self.p('b'), 'alpha')['round']['version'], 2)   # no duplicate round

    def test_respond_failure_rolls_back_the_ack(self):
        self.propose('a')
        self.error(409, self.d.sync_respond, self.p('b'), 'alpha', 1, 0, 'bad base', None, None, 'k2')
        view = self.d.sync_state(self.p('a'), 'alpha')
        self.assertEqual((view['version'], view['unacked']), (0, ['b', 'c']))             # b's ack was not recorded
        self.d.sync_ack(self.p('c'), 'alpha', 1)
        # b's ack now completes the quorum, so base 1 is valid; the failed attempt stored nothing, so key k2 is reusable
        self.assertFalse(self.d.sync_respond(self.p('b'), 'alpha', 1, 1, 'x', None, None, 'k2')['replayed'])
        self.assertEqual(self.d.sync_state(self.p('a'), 'alpha')['version'], 1)

    def test_respond_requires_key_exact_versions_and_agent_role(self):
        self.propose('a')
        self.error(400, self.d.sync_respond, self.p('b'), 'alpha', 1, 1, 'x', None, None, None)
        self.error(409, self.d.sync_respond, self.p('b'), 'alpha', 7, 1, 'x', None, None, 'k')
        self.error(403, self.d.sync_respond, self.p('watch'), 'alpha', 1, 1, 'x', None, None, 'k')

    # ---- renew ----
    def test_renew_extends_only_by_enrolled_members_and_is_capped(self):
        self.propose('a', deadline_seconds=120)
        self.now += 60
        view = self.d.sync_renew(self.p('b'), 'alpha', 1, 3600)
        self.assertAlmostEqual(view['round']['remaining'], 3600)
        self.d.sync_renew(self.p('b'), 'alpha', 1, 60)
        self.assertGreater(self.d.sync_state(self.p('a'), 'alpha')['round']['remaining'], 3000)   # never shortened
        self.d.sync_renew(self.p('b'), 'alpha', 1, 86400)
        self.assertLessEqual(self.d.sync_state(self.p('a'), 'alpha')['round']['remaining'], 86400 - 60)   # 24 h from creation
        self.error(403, self.d.sync_renew, self.p('watch'), 'alpha', 1, 600)
        self.error(409, self.d.sync_renew, self.p('b'), 'alpha', 2, 600)
        self.error(400, self.d.sync_renew, self.p('b'), 'alpha', 1, 5)

    def test_expired_round_cannot_be_renewed_and_status_does_not_extend_it(self):
        self.propose('a', deadline_seconds=60)
        self.now += 30
        self.status('b', 0, 'a')
        self.now += 31
        self.error(409, self.d.sync_renew, self.p('b'), 'alpha', 1, 600)

    # ---- resume ----
    def test_resume_reports_outstanding_action(self):
        self.assertEqual(self.d.sync_resume(self.p('a'), 'alpha')['outstanding'], 'none')
        self.propose('a', 'AGREED?')
        self.assertEqual(self.d.sync_resume(self.p('b'), 'alpha')['outstanding'], 'ack')
        mine = self.d.sync_resume(self.p('a'), 'alpha')
        self.assertEqual((mine['outstanding'], mine['round']['state']), ('wait', 'AGREED?'))
        self.agree(1)
        done = self.d.sync_resume(self.p('b'), 'alpha')
        self.assertEqual((done['outstanding'], done['committed']['version'], done['committed']['state']), ('none', 1, 'AGREED?'))
        self.assertEqual(done['proposal_seconds'], 3600)
        self.error(403, self.d.sync_resume, self.p('watch'), 'alpha')

    def test_resume_latest_id_counts_only_messages_visible_to_the_member(self):
        self.d.room_post(self.p('a'), 'alpha', ['b'], 'main', 'to b')
        self.d.room_post(self.p('a'), 'alpha', ['c'], 'main', 'to c')
        self.assertEqual(self.d.sync_resume(self.p('b'), 'alpha')['latest_id'], 1)
        self.assertEqual(self.d.sync_resume(self.p('c'), 'alpha')['latest_id'], 2)

    def test_turn_holder_with_no_round_is_told_to_respond(self):
        self.d.set_room_sync(self.admin, 'alpha', turn='b')
        self.assertEqual(self.d.sync_resume(self.p('b'), 'alpha')['outstanding'], 'respond')

    # ---- proposal deadline default and thread budget ----
    def test_proposal_seconds_is_the_default_round_deadline(self):
        self.assertEqual(self.d.set_room_sync(self.admin, 'alpha', proposal_seconds=1800)['proposal_seconds'], 1800)
        self.assertAlmostEqual(self.propose()['round']['remaining'], 1800)
        self.error(400, self.d.set_room_sync, self.admin, 'alpha', proposal_seconds=59)
        self.error(400, self.d.set_room_sync, self.admin, 'alpha', proposal_seconds=86401)
        self.d.sync_abort(self.admin, 'alpha')
        self.assertAlmostEqual(self.d.sync_propose(self.p('a'), 'alpha', 0, 'x', deadline_seconds=90)['round']['remaining'], 90)

    def test_thread_budget_reports_used_limit_and_remaining(self):
        self.assertEqual(self.d.room_thread_budget(self.p('a'), 'alpha', 'main'), {'used': 0, 'limit': 10, 'remaining': 10})
        for i in range(4):
            self.d.room_post(self.p('a'), 'alpha', ['b'], 'main', str(i))
        self.assertEqual(self.d.room_thread_budget(self.p('b'), 'alpha', 'main'), {'used': 4, 'limit': 10, 'remaining': 6})
        self.error(403, self.d.room_thread_budget, self.p('a'), 'beta', 'main')

    # ---- migration ----
    def test_v4_database_upgrades_to_v5_with_backup(self):
        self.now = None
        self.clock.stop()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'relay.db'
            store = Store(path)
            Domain(store).mint_agent('root', 'admin')
            with store.transaction() as db:
                db.execute('DROP TABLE sync_keys')
                db.execute('ALTER TABLE sync_rooms DROP COLUMN proposal_seconds')
                db.execute('ALTER TABLE messages DROP COLUMN level')
                db.execute("UPDATE settings SET value='4' WHERE key='schema_version'")
            store.close()
            upgraded = Store(path)
            upgraded.close()
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0], '5')
                self.assertIn('proposal_seconds', {r[1] for r in db.execute('PRAGMA table_info(sync_rooms)')})
                self.assertIn('level', {r[1] for r in db.execute('PRAGMA table_info(messages)')})
                self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='sync_keys'").fetchone()[0], 1)
            with closing(sqlite3.connect(str(path) + '.v4.bak')) as backup:
                self.assertEqual(backup.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0], '4')
            self.clock.start()


if __name__ == '__main__':
    unittest.main()
