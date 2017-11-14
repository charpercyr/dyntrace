
#include <stdio.h>
#include <tracer.hpp>

extern "C" void on_handle(void* caller, const dyntrace::tracer::regs& r)
{
    using namespace dyntrace::tracer;
    printf("Hit %p: a1=%ld, a2=%ld\n", caller, arg<0>(r), arg<1>(r));
}