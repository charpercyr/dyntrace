#!/usr/bin/env python3

import cli

import sys


if __name__ == '__main__':
    if sys.argv[0].endswith('dyntrace'):
        cli.main()
    else:
        print('Invalid link', sys.argv[0], file=sys.stderr)
        exit(1)