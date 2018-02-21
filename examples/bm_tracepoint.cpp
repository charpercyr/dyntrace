
#include <benchmark/benchmark.h>

#include "dyntrace/fasttp/fasttp.hpp"
#include "dyntrace/fasttp/common.hpp"

#include <syscall.h>

using namespace dyntrace;

// Similar function since a NOP has (almost) no cost.
// 2 iterations, will not trap
extern "C" void test_func_no_trap();
asm(
".type test_func_no_trap, @function\n"
"test_func_no_trap:\n"
"   nopl (%eax, %eax, 1)\n"
"   xor %rcx, %rcx\n"
".test_func_no_trap.L0:\n"
"   inc %rcx\n"
"   cmp $2, %rcx\n"
"   jne .test_func_no_trap.L0\n"
"   ret\n"
".size test_func_no_trap, . - test_func_no_trap"
);
// 2 iterations, will trap once
extern "C" void test_func_with_trap();
asm(
".type test_func_with_trap, @function\n"
"test_func_with_trap:\n"
"   xor %rcx, %rcx\n"
".test_func_with_trap.L0:\n"
"   inc %rcx\n"
"   cmp $2, %rcx\n"
"   jne .test_func_with_trap.L0\n"
"   ret\n"
".size test_func_with_trap, . - test_func_with_trap"
);

static void run_tracepoints(benchmark::State& state, void(*func)()) noexcept
{
    size_t count = 0;
    size_t trap_count = 0;

    auto handler = [&count](const void*, const arch::regs&)
    {
        ++count;
    };
    auto trap_handler = [&trap_count](const void*, const arch::regs&)
    {
        ++trap_count;
    };

    fasttp::options ops{};
    ops.x86.trap_handler = trap_handler;
    auto tp = fasttp::tracepoint{fasttp::addr_location{func}, fasttp::handler{handler}, ops};
    for(auto _ : state)
    {
        func();
    }
    state.counters["handler-call-count"] = count;
    state.counters["trap-handler-call-count"] = trap_count;
}

static void bm_run_tracepoints_no_trap(benchmark::State& state)
{
    run_tracepoints(state, test_func_no_trap);
}
BENCHMARK(bm_run_tracepoints_no_trap);

static void bm_run_tracepoints_with_trap(benchmark::State& state)
{
    run_tracepoints(state, test_func_with_trap);
}
BENCHMARK(bm_run_tracepoints_with_trap);

static void do_place_tracepoint(benchmark::State& state, const fasttp::location& loc)
{
    auto handler = [](const void*, const arch::regs&) {};

    for(auto _ : state)
    {
        fasttp::tracepoint{loc, fasttp::handler{handler}};
    }
}

static void bm_place_tracepoints_with_addr(benchmark::State& state)
{
    do_place_tracepoint(state, fasttp::addr_location{test_func_no_trap});
}
BENCHMARK(bm_place_tracepoints_with_addr);

static void bm_place_tracepoints_with_name(benchmark::State& state)
{
    do_place_tracepoint(state, fasttp::symbol_location{"test_func_no_trap"});
}
BENCHMARK(bm_place_tracepoints_with_name);

static void bm_enable_disable_tracepoints(benchmark::State& state)
{
    auto handler = [](const void*, const arch::regs&) {};
    fasttp::tracepoint tp{fasttp::addr_location{test_func_no_trap}, handler};
    for(auto _ : state)
    {
        tp.enable();
        tp.disable();
    }
}
BENCHMARK(bm_enable_disable_tracepoints);

BENCHMARK_MAIN();