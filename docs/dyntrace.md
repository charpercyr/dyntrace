# dyntrace
This sub-project is the core of dyntrace. It implements the full ecosystem to be able, from command line, to control tracepoint insertion on all processes. It is subdivised into 3 parts.

The first is the in-process agent [dyntrace-agent](#dyntrace-agent). This library is injected by the daemon into the traced process and will be responsible to control tracepoints for that process.

The second is the daemon [dyntraced](#dyntraced). This daemon is responsible to control all the agents in every traced process. It will also inject the agent if need be into the traced process. It also ensures security since it only permits users in the group `dyntrace` (or the superuser) to add tracepoints to processes.

The last is a [command line interface](#dyntrace) that communicates with the daemon and issues command. To it or to traced processes.

# dyntrace-agent
To be able to place tracepoints, this library must be loaded into the traced process. There are 3 ways of doing so.

## Link
When linking the program, add these to the linker's options.
```
-L<install>/lib/dyntrace -ldyntrace-agent
```

## LD_PRELOAD
When starting the process, add this to the command line.
```
$ LD_PRELOAD=<install>/lib/dyntrace/libdyntrace-agent.so <program> <args...>
```

## Inject
Using the command line interface, with the daemon started. The process has to be running.
```
$ dyntrace attach <pid or name>
```

# dyntraced
This program is the daemon that controls all the agents on the machine. To do anything, you must first start the daemon as a super-user.
```
# dyntraced --daemonize
```
The `--daemonize` option detaches the process from the terminal. You can remove it to block your terminal.

Only one instance of the daemon can be running at the same time.

# dyntrace
This is the main command line interface, it will be able to connect to the daemon only if the user is in the group `dyntrace`.
Here are the available commands:

```
$ dyntrace attach <pid or name>
```
Injects the agent into a process. This command must be used if the agent is not present in the process.

```
$ dyntrace list-processes
```
Lists all the processes that have the agent loaded.

```
$ dyntrace list-symbols <pid or name>
```
Lists all the functions in a given process.

```
$ dyntrace list-tracepoints <pid or name> [-a]
```
Lists all the active tracepoints in a process. The `-a` flag gives more information.

```
$ dyntrace add <pid or name>:<symbol or address> [-e] [-n name] <tracer> [tracer args...]
```
Places a tracepoint in a process at a given symbol/address. The `-e` flag creates an entry/exit tracepoint (it is called on function entry and exit). The `-n` arguments sets the name of the tracepoint, if not present, the name will be auto generated. The `tracer` argument is the name of the tracer to use when hitting the tracepoint (see [tracers](#tracer)).

This command will print the name of the created tracepoint.

```
$ dyntrace rm <pid or name>:<tracepoint name>
```

# tracers
## log
```
$ dyntrace add ... log [log file]
```
This tracer logs to a file when a tracepoint is hit. If no file is given, it will log **to the traced program's stdout**.

Do **NOT** use in a performance sensitive context since it simply writes to the file and then flushes it. Use the [lttng](#lttng) tracer instead.

## lttng
```
$ dyntrace add ... lttng
```
This tracer uses LTTng tracepoints to log tracepoint hit. The event group name is `dyntrace_lttng` for all tracepoints. For normal tracepoint, the event name is `tracepoint_hit`. For entry/exit tracepoints, the events names are `function_entry` and `function_exit`. All events contain the field `address` which contains the address of the tracepoint insertion point.