#!/usr/bin/env python3
"""Launcher for the bot2bot relay. The old shared --key mode is gone: mint per-agent tokens.

    python bot2bot_relay.py mint claude            # prints a token once
    python bot2bot_relay.py serve --port 8765
"""
import sys

from relay.__main__ import main

if __name__ == '__main__':
    if any(a == '--key' or a.startswith('--key=') or a == '--store' for a in sys.argv[1:]):
        sys.exit('--key/--store are no longer supported: tokens are per-agent. '
                 'Run "mint NAME" to create one and send it as "Authorization: Bearer <token>".')
    main()
