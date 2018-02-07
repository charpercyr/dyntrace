
import argparse
import json
import socket

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

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('command', choices=['hello', 'bye'])

    args = parser.parse_args()
    
    if args.command == 'hello':
        data = hello_msg
    elif args.command == 'bye':
        data = bye_msg
    
    data = bytes(json.dumps(data), 'utf-8')
    data = len(data).to_bytes(4, byteorder='little') + data
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    sock.connect('/tmp/dyntrace/process.sock')
    sock.send(data)

if __name__ == '__main__':
    main()