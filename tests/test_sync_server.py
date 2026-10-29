import http.client
import json
import os
import tempfile
import threading
import time
import unittest

from relay.domain import Domain
from relay.server import Hub, Watcher, make_server
from relay.store import Store

SECRET_STATE = 'PRIVATE-STATE-TEXT'
SECRET_REASON = 'PRIVATE-REASON-TEXT'


class SyncServerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), 'y.db'))
        self.domain = Domain(self.store)
        self.tok = {'root': self.domain.mint_agent('root', 'admin')}
        self.admin = {'name': 'root', 'role': 'admin', 'room': None, 'generation': 1}
        self.server = make_server(self.domain, '127.0.0.1', 0, sync_interval=0)   # no background thread: scans are explicit
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.addCleanup(self.store.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        status, body = self.call('POST', '/admin/rooms', 'root', {'name': 'alpha', 'members': ['a', 'b', 'c']})
        self.assertEqual(status, 200, body)
        for m in body['members']:
            self.tok[m['name']] = m['token']
        self.tok['eye'] = self.call('POST', '/admin/rooms/alpha/members', 'root', {'name': 'eye', 'role': 'monitor'})[1]['token']

    def call(self, method, path, who=None, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        headers = {'Authorization': f'Bearer {self.tok[who]}'} if who else {}
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode()
        conn.close()
        try:
            return resp.status, json.loads(text)
        except ValueError:
            return resp.status, text

    def propose(self, who, base, state=SECRET_STATE, **extra):
        return self.call('POST', '/rooms/alpha/state/propose', who, {'base_version': base, 'state': state, **extra})

    def commit_v1(self):
        status, body = self.propose('a', 0)
        self.assertEqual(status, 200, body)
        version = body['round']['version']
        for who in ('b', 'c'):
            self.assertEqual(self.call('POST', '/rooms/alpha/state/ack', who, {'version': version})[0], 200)
        return version

    # ---- agreement rounds ----
    def test_round_commits_only_when_everyone_acks(self):
        status, body = self.propose('a', 0)
        self.assertEqual(status, 200, body)
        version = body['round']['version']
        self.assertEqual(self.call('POST', '/rooms/alpha/state/ack', 'b', {'version': version})[0], 200)
        mid = self.call('GET', '/rooms/alpha/state', 'a')[1]
        self.assertEqual(mid['version'], 0)                    # c has not acknowledged: still not committed
        self.assertEqual(self.call('POST', '/rooms/alpha/state/ack', 'c', {'version': version})[0], 200)
        done = self.call('GET', '/rooms/alpha/state', 'b')[1]
        self.assertEqual((done['version'], done['state']), (version, SECRET_STATE))

    def test_stale_base_and_second_open_round_rejected_and_nack_aborts(self):
        status, body = self.propose('a', 0)
        self.assertEqual(status, 200)
        self.assertEqual(self.propose('b', 0)[0], 409)                          # a round is already open
        version = body['round']['version']
        self.assertEqual(self.call('POST', '/rooms/alpha/state/nack', 'b', {'version': version, 'reason': 'no'})[0], 200)
        self.assertEqual(self.call('GET', '/rooms/alpha/state', 'a')[1]['version'], 0)
        self.assertEqual(self.propose('c', 5)[0], 409)                          # base_version must equal the committed version

    def test_state_text_is_members_only(self):
        self.commit_v1()
        self.assertEqual(self.call('GET', '/rooms/alpha/state', 'eye')[0], 403)      # monitor
        self.assertEqual(self.call('GET', '/rooms/alpha/state', 'root')[0], 403)     # admin has no member route
        self.assertEqual(self.call('GET', '/admin/rooms/alpha/state', 'root')[0], 200)
        self.assertEqual(self.call('GET', '/admin/rooms/alpha/state', 'a')[0], 403)
        sync = self.call('GET', '/rooms/alpha/sync', 'eye')
        self.assertEqual(sync[0], 200)
        self.assertNotIn(SECRET_STATE, json.dumps(sync[1]))

    def test_say_and_wait_carry_sync_summary_and_strict_mode(self):
        v = self.commit_v1()
        status, body = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 't', 'text': 'hi'})
        self.assertEqual(status, 200)
        self.assertEqual(body['sync']['version'], v)
        waited = self.call('GET', '/rooms/alpha/wait?timeout=1', 'b')[1]
        self.assertEqual(waited['sync']['version'], v)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', {'strict': True})[0], 200)
        status, body = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 't', 'text': 'no version'})
        self.assertEqual((status, body['sync']['version']), (409, v))               # tells the agent what to re-sync to
        status, body = self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 't', 'text': 'stale', 'state_version': v - 1})
        self.assertEqual(status, 409)
        self.assertEqual(self.call('POST', '/rooms/alpha/say', 'a', {'to': ['b'], 'thread': 't', 'text': 'ok', 'state_version': v})[0], 200)

    # ---- stalls ----
    def declare(self, who, version, waiting_on, reason=SECRET_REASON):
        return self.call('POST', '/rooms/alpha/status', who, {'state_version': version, 'waiting_on': waiting_on, 'reason': reason})

    def test_cycle_is_detected_announced_once_and_hides_reasons(self):
        self.assertEqual(self.declare('a', 0, 'b')[0], 200)
        self.assertEqual(self.declare('b', 0, 'a')[0], 200)
        result = self.domain.sync_scan('alpha', time.time() + 1)
        self.assertEqual((result['stalled'], result['kind'], result['members']), (True, 'cycle', ['a', 'b']))
        again = self.domain.sync_scan('alpha', time.time() + 2)
        self.assertFalse(again['notify'])                                            # no duplicate notice
        got = self.call('GET', '/rooms/alpha/wait?timeout=1', 'c')[1]['messages']
        notices = [m for m in got if m['source'] == 'system']
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]['from'], 'relay')
        self.assertTrue(notices[0]['untrusted'])
        self.assertIn('cycle', notices[0]['text'])
        self.assertNotIn(SECRET_REASON, notices[0]['text'])
        sync = self.call('GET', '/rooms/alpha/sync', 'eye')[1]
        self.assertEqual((sync['stalled'], sync['kind']), (True, 'cycle'))
        self.assertEqual(sync['waiting_on']['a'], 'b')
        self.assertNotIn(SECRET_REASON, json.dumps(sync))

    def test_open_waits_count_toward_all_waiting_and_are_released(self):
        self.domain.set_room_sync(self.admin, 'alpha', stall_seconds=5)
        results = []
        threads = [threading.Thread(target=lambda w=w: results.append(self.call('GET', '/rooms/alpha/wait?timeout=3', w)))
                   for w in ('a', 'b', 'c')]
        for t in threads:
            t.start()
        time.sleep(0.7)
        scan = self.domain.sync_scan('alpha', time.time() + 30)
        self.assertEqual((scan['stalled'], scan['kind']), (True, 'all_waiting'))
        for t in threads:
            t.join(10)
        time.sleep(0.2)
        later = self.domain.sync_scan('alpha', time.time() + 60)
        self.assertNotEqual(later['kind'], 'all_waiting')                            # waits were unregistered when they returned

    # ---- admin controls ----
    def test_admin_abort_remove_reset_and_settings_over_bearer(self):
        v = self.commit_v1()
        status, body = self.propose('a', v, 'next')
        self.assertEqual(status, 200)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/abort', 'a', {})[0], 403)
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/abort', 'root', {})[0], 200)
        self.assertFalse(self.call('GET', '/rooms/alpha/sync', 'eye')[1]['round_open'])
        self.propose('a', v, 'again')
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/remove', 'root', {'name': 'c'})[0], 200)
        sync = self.call('GET', '/rooms/alpha/sync', 'eye')[1]
        self.assertNotIn('c', sync['round']['enrolled'])
        self.assertIn(self.call('POST', '/admin/rooms/alpha/sync/reset', 'root', {'version': 999})[0], (400, 404, 409))   # unknown version, or a round is open
        for bad in ({'strict': 'yes'}, {'stall_seconds': 1}, {'nonsense': 1}, {'turn': 'ghost'}):
            self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', bad)[0], 400, bad)
        status, cfg = self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', {'turn': 'a', 'auto_pass': True, 'stall_seconds': 20})
        self.assertEqual((status, cfg['turn'], cfg['auto_pass'], cfg['stall_seconds']), (200, 'a', True, 20))
        self.assertEqual(self.call('POST', '/admin/rooms/alpha/sync/settings', 'root', {'turn': None})[1]['turn'], None)

    def test_sync_routes_are_role_bound(self):
        for method, path in (('GET', '/rooms/alpha/state'), ('POST', '/rooms/alpha/status'), ('POST', '/rooms/alpha/state/ack'),
                             ('POST', '/rooms/alpha/state/propose')):
            self.assertEqual(self.call(method, path, 'eye', {})[0], 403, path)
        for path in ('/rooms/alpha/sync',):
            self.assertEqual(self.call('GET', path, 'a')[0], 403)
        self.assertEqual(self.call('POST', '/rooms/beta/state/propose', 'a', {})[0], 403)

    # ---- watcher ----
    def test_watcher_scans_enabled_rooms_wakes_waiters_and_survives_errors(self):
        from relay.domain import DomainError

        class FakeDomain:
            def __init__(self):
                self.scanned = []

            def sync_scan(self, room):
                self.scanned.append(room)
                if room == 'bad':
                    raise DomainError(404, 'gone')
                return {'notice': {'id': 1} if room == 'noisy' else None}

        class FakeHub:
            def __init__(self):
                self.domain, self.wakes = FakeDomain(), 0

            def wake(self):
                self.wakes += 1
        hub = FakeHub()
        Watcher(hub, 1, rooms=lambda: ['bad', 'quiet', 'noisy']).scan_once()
        self.assertEqual(hub.domain.scanned, ['bad', 'quiet', 'noisy'])             # an error in one room did not stop the rest
        self.assertEqual(hub.wakes, 1)                                               # woke waiters only for the room with a notice

    def test_watcher_survives_unexpected_errors_and_logs_them(self):
        class FakeDomain:
            def __init__(self):
                self.scanned = []

            def sync_scan(self, room):
                self.scanned.append(room)
                if room == 'boom':
                    raise RuntimeError('unexpected')
                return {'notice': None}

        class FakeHub:
            def __init__(self):
                self.domain = FakeDomain()

            def wake(self):
                pass
        hub = FakeHub()
        with self.assertLogs('bot2bot.relay', level='ERROR') as logs:
            Watcher(hub, 1, rooms=lambda: ['boom', 'later']).scan_once()
        self.assertEqual(hub.domain.scanned, ['boom', 'later'])      # the bad room did not starve the next one
        self.assertIn('boom', logs.output[0])                         # and the failure is observable

    def test_real_watcher_thread_announces_a_deadline_stall(self):
        self.assertEqual(self.declare('a', 0, None)[0], 200)
        self.assertEqual(self.call('POST', '/rooms/alpha/status', 'a',
                                   {'state_version': 0, 'waiting_on': 'b', 'deadline_seconds': 1})[0], 200)
        self.assertFalse(self.call('GET', '/rooms/alpha/sync', 'eye')[1]['stalled'])   # no cycle, deadline not reached yet
        server = make_server(self.domain, '127.0.0.1', 0, sync_interval=0.2)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        deadline = time.time() + 8
        notices = []
        while time.time() < deadline and not notices:
            time.sleep(0.2)
            rows = self.call('GET', '/rooms/alpha/messages?after=0', 'c')[1]['messages']
            notices = [m for m in rows if m['from'] == 'relay']
        self.assertTrue(notices, 'the watcher never recorded a system notice')
        self.assertTrue(self.call('GET', '/rooms/alpha/sync', 'eye')[1]['stalled'])

    def test_say_scans_for_stalls_and_every_say_reply_carries_sync(self):
        self.declare('a', 0, 'b')
        self.declare('b', 0, 'a')
        status, body = self.call('POST', '/rooms/alpha/say', 'c', {'to': ['a'], 'text': 'hi'})
        self.assertEqual(status, 200, body)
        self.assertIn('sync', body)
        rows = self.call('GET', '/rooms/alpha/messages?after=0', 'a')[1]['messages']
        self.assertTrue([m for m in rows if m['from'] == 'relay'])   # the say itself scanned and recorded the notice
        self.tok['old'] = self.domain.mint_agent('old', 'agent')
        self.domain.mint_agent('peer', 'agent')
        status, body = self.call('POST', '/say', 'old', {'to': 'peer', 'text': 'legacy'})
        self.assertEqual(status, 200, body)
        self.assertIn('id', body)
        self.assertIn('sync', body)

    def test_foreign_legacy_agent_cannot_trigger_a_scan_in_another_room(self):
        self.call('POST', '/rooms/alpha/status', 'a', {'state_version': 0, 'waiting_on': 'b', 'deadline_seconds': 1})
        time.sleep(1.3)    # the deadline has passed, so any scan would now record a notice
        self.tok['old'] = self.domain.mint_agent('old', 'agent')
        status, _ = self.call('POST', '/rooms/alpha/say', 'old', {'to': ['a'], 'text': 'x'})
        self.assertEqual(status, 403)
        rows = self.call('GET', '/rooms/alpha/messages?after=0', 'a')[1]['messages']
        self.assertFalse([m for m in rows if m['from'] == 'relay'])   # the rejected call scanned nothing

    def test_failed_make_server_does_not_leak_a_watcher(self):
        before = {t for t in threading.enumerate() if t.name == 'sync-watcher'}
        with self.assertRaises(ValueError):
            make_server(self.domain, '0.0.0.0', 0, sync_interval=0.2)   # non-loopback without public_origin
        after = {t for t in threading.enumerate() if t.name == 'sync-watcher'}
        self.assertEqual(before, after)

    def test_server_close_stops_the_watcher(self):
        server = make_server(self.domain, '127.0.0.1', 0, sync_interval=0.2)
        watcher = server.watcher
        self.assertTrue(watcher.is_alive())
        server.server_close()
        self.assertFalse(watcher.is_alive())


if __name__ == '__main__':
    unittest.main()
