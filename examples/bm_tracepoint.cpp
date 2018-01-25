
#include <benchmark/benchmark.h>

 #include <fasttp/fasttp.hpp>
#include <fasttp/common.hpp>

using namespace dyntrace;

extern "C" void __attribute__((noinline)) some_func() noexcept
{
    // Nothing but it tricks the compiler
    asm volatile("":::"memory");
}

static void bm_run_tracepoints(benchmark::State& state)
{
    size_t count = 0;

    auto handler = [&count](const void*, const arch::regs&)
    {
        ++count;
    };

    fasttp::options ops;
    ops.x86.disable_thread_safe = true;
    ops.x86.disable_jmp_safe = true;
    auto tp = fasttp::tracepoint{fasttp::symbol_location{"some_func"}, fasttp::handler{handler}, ops};
    for(auto _ : state)
    {
        some_func();
    }
    state.counters["handler-call-count"] = count;
}
BENCHMARK(bm_run_tracepoints);

static void do_place_tracepoint(benchmark::State& state, const fasttp::location& loc)
{
    auto handler = [](const void*, const arch::regs&) {};

    fasttp::options ops;
    ops.x86.disable_thread_safe = true;
    ops.x86.disable_jmp_safe = true;
    for(auto _ : state)
    {
        fasttp::tracepoint{loc, fasttp::handler{handler}, ops};
    }
}

static void bm_place_tracepoints_with_addr(benchmark::State& state)
{
    do_place_tracepoint(state, fasttp::addr_location{some_func});
}
BENCHMARK(bm_place_tracepoints_with_addr);

static void bm_place_tracepoints_with_name(benchmark::State& state)
{
    do_place_tracepoint(state, fasttp::symbol_location{"some_func"});
}
BENCHMARK(bm_place_tracepoints_with_name);

BENCHMARK_MAIN();