#!/usr/bin/python3

"""
dyntrace args: --socket [socket file] ...
dyntrace ... add-tracepoint <pid|name>:<addr|symbol> <tracer>
dyntrace ... remove-tracepoint <pid|name>:<name>
dyntrace ... list-tracepoint <pid|name>
dyntrace ... list-process
"""

import argparse
import re
import socket

import command_pb2
import process_pb2

next_seq = 1

debug_mode = False
def debugfunc(func):
    def inner(*args, **kwargs):
        if debug_mode:
            return func(*args, **kwargs)
    return inner


@debugfunc
def debug_print(*args, **kwargs):
    print(*args, **kwargs)


def make_msg():
    global next_seq
    msg = command_pb2.command_message()
    msg.seq = next_seq
    next_seq += 1
    return msg


def make_to_proc(proc):
    msg = make_msg()
    if isinstance(proc, int):
        msg.req.to_proc.pid = proc
    else:
        msg.req.to_proc.name = proc
    return msg


def do_request(args, req):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(args.socket)
    debug_print('=== Send ===')
    debug_print(req)
    data = bytes(req.SerializeToString())
    data = len(data).to_bytes(4, byteorder='little') + data
    sock.send(data)
    resp_size = int.from_bytes(sock.recv(4), byteorder='little')
    resp = bytes()
    while len(resp) < resp_size:
        resp += sock.recv(resp_size - len(resp))
    msg = command_pb2.command_message()
    msg.ParseFromString(resp)
    debug_print('=== Recv ===')
    debug_print(msg)
    return msg


def parse_location(location, *, sym_as_number=True):
    location = location.split(':')
    if len(location) != 2:
        raise ValueError('Invalid location')
    name, sym = location
    try:
        name = int(name)
    except ValueError:
        pass
    if sym_as_number:
        if sym.startswith('0x'):
            try:
                sym = int(sym[2:], 16)
            except ValueError:
                raise ValueError('Invalid location')
        else:
            try:
                sym = int(sym, 16)
            except ValueError:
                pass
    return name, sym


def add_tracepoint(args):
    proc, sym = parse_location(args.location)
    msg = make_to_proc(proc)
    if isinstance(sym, int):
        msg.req.to_proc.req.add_tp.tp.address = sym
    else:
        msg.req.to_proc.req.add_tp.tp.symbol = sym
    if args.name:
        msg.req.to_proc.req.add_tp.tp.name = args.name
    msg.req.to_proc.req.add_tp.tracer = args.tracer
    msg.req.to_proc.req.add_tp.tracer_args[:] = args.tracer_args
    do_request(args, msg)


def remove_tracepoint(args):
    proc, name = parse_location(args.location, sym_as_number=False)
    msg = make_to_proc(proc)
    msg.req.to_proc.req.remove_tp.name = name
    do_request(args, msg)


def list_tracepoint(args):
    proc = args.process
    try:
        proc = int(proc)
    except ValueError:
        pass
    msg = make_to_proc(proc)
    msg.req.to_proc.req.list_tp.CopyFrom(process_pb2.list_tracepoint())
    do_request(args, msg)


def list_process(args):
    msg = make_msg()
    msg.req.list_proc.CopyFrom(command_pb2.list_process())
    do_request(args, msg)


def main():
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None, parser=None)
    parser.add_argument('-s', '--socket', help='Socket file to connect to', default='/run/dyntrace/command.sock')
    parser.add_argument('--debug', help='Print debug information for the client', action='store_true')

    sps = parser.add_subparsers()

    add_tp = sps.add_parser('add-tracepoint')
    add_tp.add_argument('location', help='Where to add the tracepoint', metavar='<pid|name>:<addr|symbol>')
    add_tp.add_argument('tracer', help='The tracer to use')
    add_tp.add_argument('tracer_args', nargs='*', help='Arguments to pass to the tracer')
    add_tp.add_argument('-n', '--name', help='The unique name to give to the tracepoint (else it is auto-generated)')
    add_tp.set_defaults(func=add_tracepoint, parser=add_tp)

    rm_tp = sps.add_parser('remove-tracepoint')
    rm_tp.add_argument('location', help='The tracepoint to remove', metavar='<pid|name>:<tp_name>')
    rm_tp.set_defaults(func=remove_tracepoint, parser=rm_tp)

    list_tp = sps.add_parser('list-tracepoint')
    list_tp.add_argument('process', help='The process to list the traceponts from', metavar='<pid|name>')
    list_tp.set_defaults(func=list_tracepoint, parser=list_tp)

    list_proc = sps.add_parser('list-process')
    list_proc.set_defaults(func=list_process, parser=list_proc)

    args = parser.parse_args()

    if args.debug:
        global debug_mode
        debug_mode = True
    try:
        if not args.func:
            raise ValueError()
        args.func(args)
    except ValueError as e:
        if e.args:
            print('error: ', *e.args)
        if args.parser:
            args.parser.print_help()
        else:
            parser.print_help()
        exit(1)


if __name__ == '__main__':
    main()