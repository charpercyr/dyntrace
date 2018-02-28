
from collections import namedtuple

import command_pb2
import process_pb2


Tracepoint = namedtuple('Tracepoint', ['name', 'address', 'symbol', 'tracer', 'entry_exit', 'tracer_args'])
Symbol = namedtuple('Symbol', ['name', 'address'])


class Process:
    def __init__(self, dt, proc):
        self.dt = dt
        self.proc = proc

    def add_tracepoint(self, loc, tracer, entry_exit=False, name=None, tracer_args=None):
        req = self.__create_msg()
        if isinstance(loc, int):
            req.req.add_tp.tp.address = loc
        else:
            req.req.add_tp.tp.symbol = loc
        if name:
            req.req.add_tp.tp.name = name
        req.req.add_tp.tp.tracer = tracer
        req.req.add_tp.tp.entry_exit = entry_exit
        req.req.add_tp.tp.tracer_args[:] = tracer_args
        resp = self.dt._request_to_process(req)
        return resp.tp_created.name

    def remove_tracepoint(self, name):
        req = self.__create_msg()
        req.req.remove_tp.name = name
        self.dt._request_to_process(req)

    def list_tracepoints(self):
        req = self.__create_msg()
        req.req.list_tp.CopyFrom(process_pb2.list_tracepoint())
        resp = self.dt._request_to_process(req)
        return [
            Tracepoint(tp.name, tp.address, tp.symbol, tp.tracer, tp.entry_exit, list(tp.tracer_args))
            for tp in resp.tps.tp
        ]

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