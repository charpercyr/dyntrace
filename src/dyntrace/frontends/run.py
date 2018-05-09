
import argparse
import os
import sys
import subprocess as sp

DYNTRACE_AGENT_LIBRARY='${DYNTRACE_AGENT_LIBRARY}'
DYNTRACE_TRACER_DIRECTORY='${DYNTRACE_INSTALL_PREFIX}/${DYNTRACE_TRACER_DIRECTORY}'
DYNTRACE_VERSION='@DYNTRACE_VERSION@'

def daemonize():
    if os.fork() > 0:
        exit(0)
    os.setsid()
    os.umask(0)
    os.close(0)
    os.close(1)
    os.close(2)
    if os.fork() > 0:
        exit(0)


def main():
    parser = argparse.ArgumentParser(description='Runs a command with the dyntrace-agent pre-loaded')
    parser.add_argument('--version', help='Show version', action='store_true')
    parser.add_argument('--print', help='Print the environment variables instead of running a program', action='store_true')
    parser.add_argument('--daemonize', help='Detaches the process from the terminal', action='store_true')
    parser.add_argument('-t', '--tracer', help='Preloads a tracer', action='append')
    parser.add_argument('args', nargs='*', help='Program to run')

    args = parser.parse_args()

    if args.version:
        print(f'dyntrace {DYNTRACE_VERSION}')
        exit(0)

    preload = f'{DYNTRACE_AGENT_LIBRARY}'
    if args.tracer:
        preload += ':' + ':'.join(f'{DYNTRACE_TRACER_DIRECTORY}/{t}.so' for t in args.tracer)

    if args.print:
        print(f'LD_PRELOAD={preload}')
        exit(0)

    if len(args.args) == 0:
        parser.print_help()
        exit(1)

    if args.daemonize:
        daemonize()

    env = dict(os.environ)
    if 'LD_PRELOAD' in env:
        env['LD_PRELOAD'] += f':{preload}'
    else:
        env['LD_PRELOAD'] = f'{preload}'

    proc = sp.Popen(args.args, env=env)
    try:
        proc.communicate()
        exit(proc.returncode)
    except KeyboardInterrupt:
        exit(1)