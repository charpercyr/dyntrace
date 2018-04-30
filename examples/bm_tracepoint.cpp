
#include <benchmark/benchmark.h>

#include "dyntrace/fasttp/fasttp.hpp"
#include "dyntrace/fasttp/common.hpp"

#include <syscall.h>

using namespace dyntrace;

#if defined(__i386__) || defined(__x86_64__)
// Similar function since a NOP has (almost) no cost.
// 2 iterations, will not trap
extern "C" void test_func_no_trap();
// 2 iterations, will trap once
extern "C" void test_func_with_trap();
asm(
".type test_func_no_trap, @function\n"
".type test_func_with_trap, @function\n"
"test_func_no_trap:\n"
"   nopl (%eax, %eax, 1)\n"
"test_func_with_trap:\n"
"   xor %ecx, %ecx\n"
".test_func.L0:\n"
"   inc %ecx\n"
"   cmp $2, %ecx\n"
"   jne .test_func.L0\n"
"   ret\n"
".size test_func_no_trap, . - test_func_no_trap\n"
".size test_func_with_trap, . -test_func_with_trap\n"
);
#define test_func test_func_no_trap
#define test_func_str "test_func_no_trap"
#elif defined(__arm__) || defined(__aarch64__)
extern "C" void test_func();
asm(
".type test_func, function\n"
"test_func:\n"
"   push {lr}\n"
"   nop\n"
"   pop {pc}\n"
".size test_func, . - test_func\n"
);
#define test_func_str "test_func"
#else
#error "Architecture not supported"
#endif

static void run_tracepoints(benchmark::State& state, void(*func)()) noexcept
{
    size_t count = 0;

    auto handler = [&count](const void*, const arch::regs&)
    {
        ++count;
    };
    fasttp::options ops{};
#if defined(__i386__) || defined(__x86_64__)
    size_t trap_count = 0;
    auto trap_handler = [&trap_count](const void*, const arch::regs&)
    {
        ++trap_count;
    };
    ops.x86.trap_handler = trap_handler;
#endif
    auto tp = fasttp::tracepoint{fasttp::resolve(func), fasttp::point_handler{handler}, ops};
    for(auto _ : state)
    {
        func();
    }
    state.counters["handler-call-count"] = count;
#if defined(__i386__) || defined(__x86_64__)
    state.counters["trap-handler-call-count"] = trap_count;
#endif
}

#if defined(__i386__) || defined(__x86_64__)
static void bm_run_tracepoints_no_trap(benchmark::State& state)
#elif defined(__arm__)
static void bm_run_tracepoints(benchmark::State& state)
#endif
{
    run_tracepoints(state, test_func);
}
#if defined(__i386__) || defined(__x86_64__)
BENCHMARK(bm_run_tracepoints_no_trap);
#elif defined(__arm__)
BENCHMARK(bm_run_tracepoints);
#endif

#if defined(__i386__) || defined(__x86_64__)
static void bm_run_tracepoints_with_trap(benchmark::State& state)
{
    run_tracepoints(state, test_func_with_trap);
}
BENCHMARK(bm_run_tracepoints_with_trap);
#endif

static void bm_run_tracepoints_enter_exit(benchmark::State& state)
{
    size_t enter_count = 0;
    size_t exit_count = 0;

    auto enter = [&enter_count](const void*, const arch::regs&)
    {
        ++enter_count;
    };
    auto exit = [&exit_count](const void*, const arch::regs&)
    {
        ++exit_count;
    };

    auto tp = fasttp::tracepoint{fasttp::resolve(test_func), fasttp::entry_exit_handler{enter, exit}};
    for(auto _ : state)
    {
        test_func();
    }
    state.counters["enter-call-count"] = enter_count;
    state.counters["exit-call-count"] = exit_count;
}
BENCHMARK(bm_run_tracepoints_enter_exit);

static void do_place_tracepoint(benchmark::State& state, void* loc)
{
    auto handler = [](const void*, const arch::regs&) {};

    for(auto _ : state)
    {
        fasttp::tracepoint{loc, fasttp::point_handler{handler}};
    }
}

static void bm_place_tracepoints_with_addr(benchmark::State& state)
{
    do_place_tracepoint(state, fasttp::resolve(test_func));
}
BENCHMARK(bm_place_tracepoints_with_addr);

static void bm_place_tracepoints_with_name(benchmark::State& state)
{
    do_place_tracepoint(state, fasttp::resolve(test_func_str));
}
BENCHMARK(bm_place_tracepoints_with_name);

static void bm_enable_disable_tracepoints(benchmark::State& state)
{
    auto handler = [](const void*, const arch::regs&) {};
    fasttp::tracepoint tp{fasttp::resolve(test_func), handler};
    for(auto _ : state)
    {
        tp.enable();
        tp.disable();
    }
}
BENCHMARK(bm_enable_disable_tracepoints);

BENCHMARK_MAIN();