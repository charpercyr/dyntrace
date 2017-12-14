
#include <benchmark/benchmark.h>

 #include <fasttp/fasttp.hpp>

using namespace dyntrace;

extern "C" void __attribute__((noinline)) some_func() noexcept
{
    // Nothing but it tricks the compiler
    asm volatile("":::"memory");
}

static void bm_run_tracepoints(benchmark::State& state)
{
    auto proc = std::make_shared<process::process>(getpid());
    fasttp::context ctx{proc};

    size_t count = 0;

    auto handler = [&count](const void*, const arch::regs&)
    {
        ++count;
    };

    auto tp = ctx.create(fasttp::symbol_location{"some_func"}, fasttp::handler{handler}, fasttp::options::x86_disable_jmp_safe | fasttp::options::x86_disable_thread_safe);
    for(auto _ : state)
    {
        some_func();
    }
    state.counters["handler-call-count"] = count;
}
BENCHMARK(bm_run_tracepoints);

static void do_place_tracepoint(benchmark::State& state, const fasttp::location& loc)
{
    auto proc = std::make_shared<process::process>(getpid());
    fasttp::context ctx{proc};

    auto handler = [](const void*, const arch::regs&) {};

    for(auto _ : state)
    {
        ctx.create(loc, fasttp::handler{handler}, fasttp::options::x86_disable_jmp_safe | fasttp::options::x86_disable_thread_safe);
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