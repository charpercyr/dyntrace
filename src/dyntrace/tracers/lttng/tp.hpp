#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER dyntrace_lttng

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tp.hpp"

#if !defined(DYNTRACE_TRACERS_LTTNG_TP_HPP_) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DYNTRACE_TRACERS_LTTNG_TP_HPP_

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    dyntrace_lttng,
    func_entry ,
    TP_ARGS(
        const void*, address_arg
    ),
    TP_FIELDS (
        ctf_integer_hex(const void*, address_field, address_arg)
    )
)

#endif

#include <lttng/tracepoint-event.h>