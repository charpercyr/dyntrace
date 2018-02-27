#include "dyntrace/tracer.hpp"

#include "tp.hpp"

using namespace dyntrace::tracer;

extern "C" point_handler create_point_handler(const std::vector<std::string>& args)
{
    return [](const void* addr, const dyntrace::arch::regs&)
    {
        tracepoint(dyntrace_lttng, tracepoint_hit, addr);
    };
}

extern "C" entry_exit_handler create_entry_exit_handler(const std::vector<std::string>&)
{
    return {
        [](const void* addr, const dyntrace::arch::regs&)
        {
            tracepoint(dyntrace_lttng, function_entry, addr);
        },
        [](const void* addr, const dyntrace::arch::regs&)
        {
            tracepoint(dyntrace_lttng, function_exit, addr);
        }
    };
}