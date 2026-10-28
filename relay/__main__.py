"""CLI: python -m relay [--db PATH] {serve,mint,revoke,pause,resume,reset-thread,room,inject,watch}

Room and inject commands act as the local administrator (they need the database file, not a token)."""
import argparse
import sys
import time

from .domain import Domain, DomainError
from .server import make_server
from .store import Store


def _admin(store):
    """The local administrator principal used by CLI management commands."""
    with store.transaction(read_only=True) as db:
        row = db.execute("SELECT name FROM agents WHERE role='admin' AND active=1 ORDER BY rowid LIMIT 1").fetchone()
    if row is None:
        sys.exit('error: no active admin; start the server once to create one')
    return {'name': row['name'], 'role': 'admin', 'room': None, 'generation': 1}


def _when(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) if isinstance(ts, (int, float)) else '-'


def _recipients(text):
    return '*' if text == '*' else [n for n in text.split(',') if n]


def build_parser():
    ap = argparse.ArgumentParser(prog='relay', description=__doc__)
    ap.add_argument('--db', default='relay.db', help='SQLite file (default relay.db)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    serve = sub.add_parser('serve', help='run the relay')
    serve.add_argument('--host', default='127.0.0.1', help='use 0.0.0.0 to accept other machines')
    serve.add_argument('--port', type=int, default=8765)
    mint = sub.add_parser('mint', help='(default room) create an identity and print its token once')
    mint.add_argument('name')
    mint.add_argument('--role', choices=['agent', 'observer', 'admin'], default='agent')
    sub.add_parser('pause', help='kill switch: block agent writes in ALL rooms (global; the human can still inject)')
    sub.add_parser('resume', help='lift the pause')
    revoke = sub.add_parser('revoke', help='(default room) deactivate an identity')
    revoke.add_argument('name')
    reset = sub.add_parser('reset-thread', help='(default room) restore a thread message budget')
    reset.add_argument('thread')

    room = sub.add_parser('room', help='manage rooms').add_subparsers(dest='room_cmd', required=True)
    create = room.add_parser('create', help='create a room and print each member token once')
    create.add_argument('name')
    create.add_argument('--members', default='', help='comma-separated agent names')
    room.add_parser('list', help='rooms with member counts and activity')
    for verb in ('close', 'reopen'):
        room.add_parser(verb, help=f'{verb} a room').add_argument('name')
    members = room.add_parser('members', help='who is in a room and who is active')
    members.add_argument('name')
    mm = room.add_parser('mint', help='add a member and print its token once')
    mm.add_argument('name')
    mm.add_argument('member')
    mm.add_argument('--role', choices=['agent', 'monitor'], default='agent')
    for verb in ('revoke', 'rotate'):
        v = room.add_parser(verb, help=f'{verb} a member token')
        v.add_argument('name')
        v.add_argument('member')
    rt = room.add_parser('reset-thread', help='restore a thread budget')
    rt.add_argument('name')
    rt.add_argument('thread')

    inject = sub.add_parser('inject', help='send a message as the human')
    inject.add_argument('room')
    inject.add_argument('--to', default='*', help="'*' (everyone, default) or comma-separated names")
    inject.add_argument('--thread', default='human')
    inject.add_argument('text')
    watch = sub.add_parser('watch', help='live metadata-only view of a room (no message text)')
    watch.add_argument('room')
    watch.add_argument('--interval', type=float, default=1.0)
    return ap


def _members_table(domain, admin, name):
    for m in domain.members(admin, name):
        mark = 'active' if m.get('active') else 'idle'
        print(f"{m['name']:<20} {m['role']:<8} {mark:<7} last_seen={_when(m.get('last_seen'))}")


def _watch(domain, admin, room, interval):
    after = 0
    print(f'watching room {room} (metadata only; Ctrl-C to stop)')
    try:
        while True:
            for e in domain.monitor(admin, room, after, 100):
                after = e['id']
                print(f"[{e['id']}] {time.strftime('%H:%M:%S', time.localtime(e['ts']))} "
                      f"{e['from']} -> {e['to_count']} recipient(s) {e['bytes']} B thread#{e['thread_no']} ({e['source']})")
            time.sleep(interval)
    except KeyboardInterrupt:
        print()


def run(args, store, domain):
    cmd = args.cmd
    if cmd == 'serve':
        with store.transaction(read_only=True) as db:
            has_admin = db.execute("SELECT 1 FROM agents WHERE role='admin' AND active=1").fetchone()
        if not has_admin:
            print('first start; admin token (shown once):', domain.mint_agent('admin', 'admin'))
        server = make_server(domain, args.host, args.port)
        print(f'relay on http://{args.host}:{args.port} db={args.db}')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    elif cmd == 'mint':
        print(domain.mint_agent(args.name, args.role))
    elif cmd == 'revoke':
        domain.revoke(args.name)
    elif cmd == 'pause':
        domain.pause()
    elif cmd == 'resume':
        domain.resume()
    elif cmd == 'reset-thread':
        domain.reset_thread(args.thread)
    elif cmd == 'inject':
        env = domain.inject(_admin(store), args.room, _recipients(args.to), args.thread, args.text)
        print(f"injected message {env['id']}")
    elif cmd == 'watch':
        _watch(domain, _admin(store), args.room, args.interval)
    elif cmd == 'room':
        admin = _admin(store)
        sub = args.room_cmd
        if sub == 'create':
            names = [n for n in args.members.split(',') if n]
            result = domain.create_room(admin, args.name, names)
            print(f"room {result['room']} created")
            for m in result['members']:
                print(f"{m['name']}: {m['token']}")
        elif sub == 'list':
            for r in domain.list_rooms(admin):
                print(f"{r['name']:<20} {r['status']:<7} members={r.get('members')} active={r.get('active')} "
                      f"last_activity={_when(r.get('last_activity'))}")
        elif sub in ('close', 'reopen'):
            domain.set_room_closed(admin, args.name, sub == 'close')
        elif sub == 'members':
            _members_table(domain, admin, args.name)
        elif sub == 'mint':
            print(domain.mint_member(admin, args.name, args.member, args.role))
        elif sub == 'revoke':
            domain.revoke_member(admin, args.name, args.member)
        elif sub == 'rotate':
            print(domain.rotate_member(admin, args.name, args.member))
        elif sub == 'reset-thread':
            domain.reset_room_thread(admin, args.name, args.thread)


def main(argv=None):
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    domain = Domain(store)
    try:
        run(args, store, domain)
    except DomainError as err:
        sys.exit(f'error {err.code}: {err.message}')
    finally:
        store.close()


if __name__ == '__main__':
    main()
