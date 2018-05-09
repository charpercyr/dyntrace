
#include <dyntrace/tracer.hpp>

using namespace dyntrace::tracer;

void do_nothing(const void*, const dyntrace::arch::regs&){}

extern "C" point_handler create_point_handler()
{
    return {do_nothing};
}

extern "C" entry_exit_handler create_entry_exit_handler()
{
    return {do_nothing, do_nothing};
}