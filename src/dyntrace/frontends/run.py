
import argparse
import os
import sys
import subprocess as sp

DYNTRACE_AGENT_LIBRARY='${DYNTRACE_AGENT_LIBRARY}'

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
    parser.add_argument('--print', help='Print the environment variables instead of running a program', action='store_true')
    parser.add_argument('--daemonize', help='Detaches the process from the terminal', action='store_true')
    parser.add_argument('args', nargs='*', help='Program to run')

    args = parser.parse_args()

    if args.print:
        print(f'LD_PRELOAD={DYNTRACE_AGENT_LIBRARY}')
        exit(0)

    if len(args.args) == 0:
        parser.print_help()
        exit(1)

    if args.daemonize:
        daemonize()

    env = dict(os.environ)
    if 'LD_PRELOAD' in env:
        env['LD_PRELOAD'] += f':{DYNTRACE_AGENT_LIBRARY}'
    else:
        env['LD_PRELOAD'] = f'{DYNTRACE_AGENT_LIBRARY}'

    proc = sp.Popen(args.args, env=env)
    try:
        proc.communicate()
        exit(proc.returncode)
    except KeyboardInterrupt:
        exit(1)