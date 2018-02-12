
import argparse
import json
import socket

import process_pb2

hello_msg = {
    'seq': 0,
    'body': {
        'type': 'hello',
        'pid': -1
    }
}
bye_msg = {
    'seq': 1,
    'body': {
        'type': 'bye'
    }
}
request_msg = {
    #'seq': 2,
    'body': {
        'type': 'request',
        'request': 'invalid'
    }
}

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('command', choices=['hello', 'bye', 'req'])

    args = parser.parse_args()
    
    if args.command == 'hello':
        data = hello_msg
    elif args.command == 'bye':
        data = bye_msg
    elif args.command == 'req':
        data = request_msg
    
    data = bytes(json.dumps(data, separators=(',', ':')), 'utf-8')
    data = len(data).to_bytes(4, byteorder='little') + data
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    sock.connect('/tmp/dyntrace/process.sock')
    print(str(data[4:], 'utf-8'))
    for _ in range(10):
        sock.send(data)
        if args.command == 'req':
            rep = sock.recv(4096)
            print(str(rep[4:], 'utf-8'))

if __name__ == '__main__':
    main()