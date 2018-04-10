
from collections import namedtuple

from dyntrace.common import DyntraceError

import command_pb2
import process_pb2

TracepointGroup = namedtuple(
    'TracepointGroup',
    ['name', 'location', 'entry_exit', 'tracer', 'tracer_args', 'tps']
)
Tracepoint = namedtuple(
    'Tracepoint',
    ['symbol', 'address', 'id', 'failed']
)
Symbol = namedtuple(
    'Symbol',
    ['name', 'address']
)


class Process:
    def __init__(self, dt, proc):
        self.dt = dt
        self.proc = proc

    def add_tracepoint(self, tracer, entry_exit=False, name=None, tracer_args=None, filter=None, regex=None, addr=None, lib=None):
        req = self.__create_msg()
        if not filter and not regex and not addr:
            raise ValueError('Must specify one of filter, regex or addr')
        if filter:
            req.req.add_tp.filter.name = filter
        elif regex:
            req.req.add_tp.filter.name = regex
            req.req.add_tp.filter.regex = True
        else:
            req.req.add_tp.address = addr
        if lib:
            req.req.add_tp.filter.lib = lib
        if name:
            req.req.add_tp.name = name
        req.req.add_tp.tracer = tracer
        req.req.add_tp.entry_exit = entry_exit
        req.req.add_tp.tracer_args[:] = tracer_args
        resp = self.dt._request_to_process(req)
        return resp.tp_created.name, list(resp.tp_created.failed)

    def remove_tracepoint(self, name, ids=None):
        req = self.__create_msg()
        req.req.remove_tp.name = name
        if ids:
            req.req.remove_tp.id[:] = ids
        self.dt._request_to_process(req)

    def list_tracepoints(self):
        req = self.__create_msg()
        req.req.list_tp.CopyFrom(process_pb2.list_tracepoint())
        resp = self.dt._request_to_process(req)
        res = []
        for tg in resp.tps.tgs:
            if tg.filter:
                location = tg.filter
            elif tg.regex:
                location = tg.regex
            else:
                location = hex(tg.address)
            res += [TracepointGroup(
                tg.name,
                location,
                'entry_exit' if tg.entry_exit else 'point',
                tg.tracer,
                list(tg.tracer_args),
                []
            )]
            for tp in tg.tps:
                res[-1].tps.append(Tracepoint(
                    tp.symbol if tp.symbol else None,
                    hex(tp.address) if not tp.failed else None,
                    tp.id,
                    tp.failed
                ))
        return res

    def list_symbols(self):
        req = self.__create_msg()
        req.req.list_sym.CopyFrom(process_pb2.list_symbol())
        resp = self.dt._request_to_process(req)
        return [Symbol(s.name, s.address) for s in resp.syms.sym]

    def __create_msg(self):
        msg = command_pb2.process_request()
        if isinstance(self.proc, int):
            msg.pid = self.proc
        else:
            msg.name = self.proc
        return msg