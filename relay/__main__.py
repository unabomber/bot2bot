"""CLI: python -m relay {serve,mint,revoke,pause,resume,reset-thread} --db PATH"""
import argparse
import sys

from .domain import Domain, DomainError
from .server import make_server
from .store import Store


def main(argv=None):
    ap = argparse.ArgumentParser(prog='relay', description=__doc__)
    ap.add_argument('--db', default='relay.db', help='SQLite file (default relay.db)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    serve = sub.add_parser('serve', help='run the relay')
    serve.add_argument('--host', default='127.0.0.1', help='use 0.0.0.0 to accept other machines')
    serve.add_argument('--port', type=int, default=8765)
    mint = sub.add_parser('mint', help='create an identity and print its token once')
    mint.add_argument('name')
    mint.add_argument('--role', choices=['agent', 'observer', 'admin'], default='agent')
    sub.add_parser('pause', help='kill switch: block all agent writes')
    sub.add_parser('resume', help='lift the pause')
    revoke = sub.add_parser('revoke', help='deactivate an identity')
    revoke.add_argument('name')
    reset = sub.add_parser('reset-thread', help='restore a thread message budget')
    reset.add_argument('thread')
    args = ap.parse_args(argv)

    store = Store(args.db)
    domain = Domain(store)
    try:
        if args.cmd == 'serve':
            with store.transaction() as db:
                has_admin = db.execute("SELECT 1 FROM agents WHERE role='admin' AND active=1").fetchone()
            if not has_admin:
                print('first start; admin token (shown once):', domain.mint_agent('admin', 'admin'))
            server = make_server(domain, args.host, args.port)
            print(f'relay on http://{args.host}:{args.port} db={args.db}')
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        elif args.cmd == 'mint':
            print(domain.mint_agent(args.name, args.role))
        elif args.cmd == 'revoke':
            domain.revoke(args.name)
        elif args.cmd == 'pause':
            domain.pause()
        elif args.cmd == 'resume':
            domain.resume()
        elif args.cmd == 'reset-thread':
            domain.reset_thread(args.thread)
    except DomainError as err:
        sys.exit(f'error {err.code}: {err.message}')
    finally:
        store.close()


if __name__ == '__main__':
    main()
