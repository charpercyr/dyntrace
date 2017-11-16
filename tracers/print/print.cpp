
#include <cstdio>
#include <tracer.hpp>

extern "C" void on_enter(void* caller, const dyntrace::tracer::regs& r) noexcept
{
    using namespace dyntrace::tracer;
    printf("Hit %p: a1=%ld\n", caller, arg<0>(r));
}

extern "C" void on_exit(void* caller, const dyntrace::tracer::regs& r) noexcept
{
    using namespace dyntrace::tracer;
    printf("Hit %p: a1=%ld\n", caller, arg<0>(r));
}