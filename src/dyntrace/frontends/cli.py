
from dyntrace.dyntrace import Dyntrace

def main():
    dt = Dyntrace('/tmp/dyntrace/command.sock')
    print(dt.list_processes())