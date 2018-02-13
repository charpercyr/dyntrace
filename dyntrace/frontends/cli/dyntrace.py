
import argparse
import json
import socket

import process_pb2

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('command', choices=['hello', 'bye', 'req'])

    args = parser.parse_args()
    
    if args.command == 'hello':
        msg = process_pb2.process_message()
        msg.seq = 0
        msg.hello.pid = -1
    elif args.command == 'bye':
        msg = process_pb2.process_message()
        msg.seq = 1
        msg.bye.CopyFrom(process_pb2.bye())
    elif args.command == 'req':
        msg = process_pb2.process_message()
        msg.seq = 2
        msg.req.list_tp.CopyFrom(process_pb2.list_tracepoint())
    
    data = msg.SerializeToString()
    print(msg, f'({len(data)})')
    data = len(data).to_bytes(4, byteorder='little') + data
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    sock.connect('/tmp/dyntrace/process.sock')
    for _ in range(10):
        sock.send(data)
        if args.command == 'req':
            buf = sock.recv(4096)
            rep = process_pb2.process_message()
            rep.ParseFromString(buf[4:])
            print(rep)

if __name__ == '__main__':
    main()