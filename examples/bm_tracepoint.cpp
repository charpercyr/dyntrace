
#include <benchmark/benchmark.h>

#include <fasttp/fasttp.hpp>

extern "C" void some_func(int* a, int b) noexcept
{
    for(int i = 0; i < b; ++i)
    {
        *a += b;
        *a = (((*a) & 0xff) << 24) | ((*a) >> 8);
    }
}

static size_t count;
static void handler(const void*, const dyntrace::tracer::regs&)
{
    ++count;
}

static void bm_no_tracepoints(benchmark::State& state)
{
    int a = 0;
    for(auto _ : state)
    {
        some_func(&a, 1000);
    }
    printf("%d\n", a);
}
BENCHMARK(bm_no_tracepoints);

static void bm_with_tracepoints(benchmark::State& state)
{
    using namespace dyntrace;

    auto proc = std::make_shared<process::process>(getpid());
    fasttp::context ctx{proc};
    auto tp = ctx.create(fasttp::symbol_location{"some_func"}, fasttp::handler{handler});

    count = 0;
    int a = 0;

    for(auto _ : state)
    {
        some_func(&a, 1000);
    }

    printf("Called %lu times\n", count);
    printf("%d\n", a);
}
BENCHMARK(bm_with_tracepoints);

BENCHMARK_MAIN();