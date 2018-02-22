#include "dyntrace/tracer.hpp"

#include "tp.hpp"

DYNTRACE_CREATE_HANDLER(args)
{
    return DYNTRACE_HANDLER(addr,)
    {
        tracepoint(dyntrace_lttng, func_entry, addr);
    };
}