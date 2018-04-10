#!/usr/bin/env python3

import importlib

import sys

DYNTRACE_CLIENTS = '${DYNTRACE_CLIENTS}'

if __name__ == '__main__':
    clients = {}
    for c in DYNTRACE_CLIENTS.split(';'):
        command, mod = c.split('@')
        clients[command] = importlib.import_module(mod)
    for c, m in clients.items():
        if sys.argv[0].endswith(c):
            m.main()
            exit(0)
    print('Invalid link', sys.argv[0], file=sys.stderr)
    exit(1)