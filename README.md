# dyntrace
This project implements a fast tracepoint insertion ecosystem for x86(_64) on Linux.

# Getting Started
## Prerequesites
To build the library, you must install the following.

Libraries
- [boost 1.66+](http://www.boost.org/users/download/)
- [libelfin](https://github.com/aclements/libelfin)
- [Capstone](http://www.capstone-engine.org/)
- [Google Protocol Buffers](https://developers.google.com/protocol-buffers/)

Programs
- [Python 3.6+](https://www.python.org/downloads/)
- [Cmake 3+](https://cmake.org/download/)
- C++17 capable compiler and libraries

## Building & Installing
```
mkdir build
cmake ..
make
sudo make install
```
After this, you must create the dyntrace group.
```
sudo groupadd dyntrace
sudo usermod -aG dyntrace <your username>
```

## Simple usage
First, start the dyntraced daemon.
```
sudo dyntraced --daemonize
```
Then attach to any program. If your user is not in the dyntrace group, you won't be allowed to do this command.
```
dyntrace attach <pid or name>
```
Then add a tracepoint. It will log to the file /tmp/test.log.
```
dyntrace add <pid or name>:<function name or address> log /tmp/test.log
```
There will be an output on the command line, this is the name of the tracepoint with the form `tp-#`

Wait a bit, then remove the tracepoint.
```
dyntrace rm <pid or name>:tp-#
```

Full example:
```
sudo dyntraced --daemonize
dyntrace attach nano
dyntrace add nano:do_home lttng
...
dyntrace rm nano:tp-0
sudo pkill dyntraced
```
More details in the [docs](docs/) folder.

<aside class="notice">
To trace x86 programs, you need the x86 build on x64.
</aside>

# TODO
- ARM (32 and 64 bit) support
- Tracepoint name filters (wildcard + regex)
- Tracepoint arguments filters (only trace if condition is true)
- Tracepoint groups (Multiple tracepoints under the same name for easier control)

# Contact
Christian Harper-Cyr <charpercyr@gmail.com>
