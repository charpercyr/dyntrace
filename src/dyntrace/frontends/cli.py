
import argparse
import sys

from dyntrace.dyntrace import Dyntrace, DyntraceError
import dyntrace.debug as debug


def parse_process(proc):
    try:
        return int(proc)
    except ValueError:
        return proc


def parse_location(loc):
    if loc.startswith('0x'):
        return int(loc[2:], 16)
    else:
        try:
            return int(loc, 16)
        except ValueError:
            return loc


def parse_process_and_location(proc, location_as_int):
    proc = proc.split(':')
    if len(proc) != 2:
        raise ValueError('Invalid location')
    proc, loc = proc
    proc = parse_process(proc)
    if location_as_int:
        loc = parse_location(loc)
    return proc, loc


def do_add(dt, args):
    proc, loc = parse_process_and_location(args.location, True)
    print(dt.process(proc).add_tracepoint(loc, args.tracer, args.entry_exit, args.name, args.tracer_args))


def do_rm(dt, args):
    proc, name = parse_process_and_location(args.location, False)
    dt.process(proc).remove_tracepoint(name)


def do_list(dt, args):
    proc = parse_process(args.process)
    for tp in dt.process(proc).list_tracepoints():
        line = f'[{tp.name}] '
        if tp.symbol:
            line += f'{tp.symbol} ('
        line += f'{hex(tp.address)}'
        if tp.symbol:
            line += ')'
        if args.all:
            if tp.entry_exit:
                line += ' [entry_exit]'
            else:
                line += ' [point]'
            line += ' ' + tp.tracer
            if tp.tracer_args:
                line += '("' + '", "'.join(tp.tracer_args) + '")'
            else:
                line += '()'
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
        default='@DYNTRACE_WORKING_DIRECTORY@/@DYNTRACE_COMMAND_SOCKET_NAME@'
    )

    add = sps.add_parser('add')
    add.set_defaults(parser=add, func=do_add)
    add.add_argument('location', help='Where to put the tracepoint', metavar='<pid|name>:<addr|sym>')
    add.add_argument('tracer', help='Tracer to use')
    add.add_argument('tracer_args', nargs='*', help='Arguments to pass to the tracer')
    add.add_argument('-n', '--name', help='Name to give to the tracepoint, default is auto-generated')
    add.add_argument(
        '-e', '--entry-exit',
        help='Create an entry/exit tracepoint, must be at the beginning of a function (else it crashes)',
        action='store_true'
    )

    rm = sps.add_parser('rm')
    rm.set_defaults(parser=rm, func=do_rm)
    rm.add_argument('location', help='Which tracepoint to remove', metavar='<pid|name>:<tp_name>')

    list_ = sps.add_parser('list')
    list_.set_defaults(parser=list_, func=do_list)
    list_.add_argument('process', help='Which process to list tracepoints from', metavar='<pid|name>')
    list_.add_argument('-a', '--all', help='Print additional information', action='store_true')

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
