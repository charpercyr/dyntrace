
import socket
import sys

import command_pb2

class Connection:
    def __init__(self, socket_file):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(socket_file)

    def request(self, req):
        msg = req.SerializeToString()
        size = len(msg)
        msg = size.to_bytes(4, byteorder=sys.byteorder) + msg
        self.sock.send(msg)
        size = self.sock.recv(4)
        size = int.from_bytes(size, byteorder=sys.byteorder)
        msg = self.sock.recv(size)
        resp = command_pb2.command_message()
        resp.ParseFromString(msg)
        return resp