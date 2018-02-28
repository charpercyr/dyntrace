
from dyntrace.connection import Connection
from dyntrace.debug import debug_print
from dyntrace.process import Process
import command_pb2

class DyntraceError(Exception):
    pass

class Dyntrace:
    def __init__(self, socket_file):
        self.conn = Connection(socket_file)
        self.next_seq = 1

    def process(self, proc):
        return Process(self, proc)

    def list_processes(self):
        req = self.__create_message()
        req.req.list_proc.CopyFrom(command_pb2.list_process())
        debug_print(req)
        resp = self.conn.request(req)
        debug_print(resp)
        resp = resp.resp
        self.__check_error(resp)
        return [pid for pid in resp.ok.procs.pids]

    def _request_to_process(self, to_proc):
        req = self.__create_message()
        req.req.to_proc.CopyFrom(to_proc)
        resp = self.conn.request(req)
        self.__check_error(resp)
        return resp.ok

    def __check_error(self, resp):
        if resp.HasField('err'):
            raise DyntraceError(resp.err.type, resp.err.msg)

    def __create_message(self):
        msg = command_pb2.command_message()
        msg.seq = self.next_seq
        self.next_seq += 1
        return msg