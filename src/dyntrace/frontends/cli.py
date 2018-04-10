
import argparse
import sys

from dyntrace.dyntrace import Dyntrace, DyntraceError
import dyntrace.debug as debug


SOCKET_FILE='@DYNTRACE_WORKING_DIRECTORY@/@DYNTRACE_COMMAND_SOCKET_NAME@'


def parse_process(proc):
    try:
        return int(proc)
    except ValueError:
        return proc


def parse_process_and_location(proc):
    proc = proc.split(':')
    if len(proc) != 2:
        raise ValueError('Invalid location')
    proc, loc = proc
    return parse_process(proc), loc


def do_add(dt, args):
    proc, loc = parse_process_and_location(args.location)
    address = None
    filter = None
    regex = None
    if args.address:
        if loc.startswith('0x'):
            loc = loc[2:]
        address = int(loc, 16)
    elif args.regex:
        regex = loc
    else:
        filter = loc
    name, err = dt.process(proc).add_tracepoint(
        args.tracer,
        args.entry_exit,
        args.name,
        args.tracer_args,
        filter, regex, address
    )
    print(name)
    for e in err:
        print('#' + str(e.id) + ' failed:', e.msg)
    if err:
        exit(1)


def do_rm(dt, args):
    proc, name = parse_process_and_location(args.location)
    dt.process(proc).remove_tracepoint(name)


def do_list(dt, args):
    proc = parse_process(args.process)
    for tg in dt.process(proc).list_tracepoints():
        line = f'[{tg.name}] {tg.location}'
        if args.all:
            if tg.entry_exit:
                line += ' [entry_exit]'
            else:
                line += ' [point]'
            line += ' ' + tg.tracer
            if tg.tracer_args:
                line += '("' + '", "'.join(tg.tracer_args) + '")'
            else:
                line += '()'
        print(line)
        if args.all:
            for tp in tg.tps:
                line = f'  #{tp.id}:'
                if tp.failed:
                    line += ' failed'
                else:
                    if tp.symbol:
                        line += ' ' + tp.symbol
                    line += f' ({tp.address})'
                print(line)


def do_attach(dt, args):
    proc = parse_process(args.process)
    dt.attach(proc)


def do_list_symbols(dt, args):
    proc = parse_process(args.process)
    print_name = args.name or (not args.name and not args.addr)
    print_addr = args.addr or (not args.name and not args.addr)
    for s in dt.process(proc).list_symbols():
        line = ''
        if print_name:
            line += s.name
        if print_name and print_addr:
            line += ' ('
        if print_addr:
            line += hex(s.address)
        if print_name and print_addr:
            line += ')'
        print(line)


def do_list_processes(dt, args):
    print_pid = args.pid or (not args.pid and not args.cmdline)
    print_cmdline = args.cmdline or (not args.pid and not args.cmdline)
    for proc in dt.list_processes():
        line = ''
        if print_pid and print_cmdline:
            line += '['
        if print_pid:
            line += str(proc.pid)
        if print_pid and print_cmdline:
            line += '] '
        if print_cmdline:
            line += ' '.join(proc.cmdline)
        print(line)


def main():

    parser = argparse.ArgumentParser()
    sps = parser.add_subparsers()
    parser.add_argument('--debug', help='Debug mode, prints more information', action='store_true')
    parser.add_argument(
        '-s', '--socket',
        help='Socket to connect to',
        default=SOCKET_FILE
    )

    add = sps.add_parser('add')
    add.set_defaults(parser=add, func=do_add)
    add.add_argument(
        'location',
        help='Where to put the tracepoints, the filter is a string with wildcard.',
        metavar='<pid|name>:<filter>'
    )
    add.add_argument(
        '-n', '--name',
        help='Name to give to the tracepoint, default is auto-generated'
    )
    add.add_argument(
        '-e', '--entry-exit',
        help='Create entry/exit tracepoints, must be at the beginning of a function (else it crashes)',
        action='store_true'
    )
    add_rx = add.add_mutually_exclusive_group()
    add_rx.add_argument(
        '-r', '--regex',
        help='Filter is a regular expression',
        action='store_true'
    )
    add_rx.add_argument(
        '-x', '--address',
        help='Location is an address',
        action='store_true'
    )
    add.add_argument('tracer', help='Tracer to use')
    add.add_argument('tracer_args', nargs='*', help='Arguments to pass to the tracer')

    rm = sps.add_parser('rm')
    rm.set_defaults(parser=rm, func=do_rm)
    rm.add_argument('location', help='Which tracepoints to remove', metavar='<pid|name>:<tp_group_name>[#n[,n...]]')

    list_ = sps.add_parser('list')
    list_.set_defaults(parser=list_, func=do_list)
    list_.add_argument('process', help='Which process to list tracepoints from', metavar='<pid|name>')
    list_.add_argument('-a', '--all', help='Print all tracepoints', action='store_true')
    list_.add_argument('group', help='Print tracepoints for one group', nargs='?')

    list_symbols = sps.add_parser('list-symbols')
    list_symbols.set_defaults(parser=list_symbols, func=do_list_symbols)
    list_symbols.add_argument('process', help='Which process to list tracepoints from', metavar='<pid|name>')
    list_symbols.add_argument('--name', help='Only print the name', action='store_true')
    list_symbols.add_argument('--addr', help='Only print the address', action='store_true')

    list_processes = sps.add_parser('list-processes')
    list_processes.set_defaults(parser=list_processes, func=do_list_processes)
    list_processes.add_argument('--pid', help='Only print the pids', action='store_true')
    list_processes.add_argument('--cmdline', help='Only print the command line', action='store_true')

    attach = sps.add_parser('attach')
    attach.set_defaults(parser=attach, func=do_attach)
    attach.add_argument('process', help='Which process to attach', metavar='<pid|name>')

    args = parser.parse_args()
    debug.set_debug(args.debug)

    if not hasattr(args, 'func'):
        parser.print_help()
        exit(1)

    try:
        dt = Dyntrace(args.socket)
    except OSError:
        print(f'Could not open socket file {args.socket}, is dyntraced running ?')
        exit(1)

    try:
        args.func(dt, args)
    except ValueError as e:
        print(e)
        args.parser.print_help()
    except DyntraceError as e:
        print(e.args[0].replace('_', ' ') + ':', e.args[1], file=sys.stderr)
        exit(1)
