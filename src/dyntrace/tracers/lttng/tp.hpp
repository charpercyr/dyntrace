#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER dyntrace_lttng

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tp.hpp"

#if !defined(DYNTRACE_TRACERS_LTTNG_TP_HPP_) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DYNTRACE_TRACERS_LTTNG_TP_HPP_

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT_CLASS(
    dyntrace_lttng,
    dyntrace_tracepoint,
    TP_ARGS(
        const void*, address
    ),
    TP_FIELDS(
        ctf_integer_hex(const void*, address, address)
    )
)

TRACEPOINT_EVENT_INSTANCE(
    dyntrace_lttng,
    dyntrace_tracepoint,
    function_entry,
    TP_ARGS(
        const void*, address
    )
)

TRACEPOINT_EVENT_INSTANCE(
    dyntrace_lttng,
    dyntrace_tracepoint,
    function_exit,
    TP_ARGS(
        const void*, address
    )
)

TRACEPOINT_EVENT_INSTANCE(
    dyntrace_lttng,
    dyntrace_tracepoint,
    tracepoint_hit,
    TP_ARGS(
        const void*, address
    )
)

#endif

#include <lttng/tracepoint-event.h>