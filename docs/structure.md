# Sub-projects
This project contains 3 sub-projects.

## fasttp
This project contains the implementation of fast tracepoints. These tracepoints can be placed (almost) anywhere in the code and have minimum overhead. More detail in [docs/fasttp.md](../docs/fasttp.md)

## inject
This project contains the implemtation of a library injector. This library has a simple to use interface that injects any library into any process. More details in [docs/inject.md](../docs/inject.md)

## dyntrace
This project uses the previous libraries and is a full ecosystem to add fast tracepoints into any running program.
More details in [docs/dyntrace.md](../docs/dyntrace.md)