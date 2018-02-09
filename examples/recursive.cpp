#include <cstdio>
#include <fasttp/fasttp.hpp>
#include <thread>
#include <fasttp/common.hpp>

using namespace dyntrace;

extern "C" int __attribute__((noinline)) fib(int n, int lvl = 0)
{
    if(n <= 1)
        return 1;
    else
        return fib(n - 2, lvl + 1) + fib(n - 1, lvl + 1);
}

int main()
{
    auto handler = [](const void *caller, int n)
    {
        using arch::arg;
        printf("fib(%d)\n", n);
    };

    fasttp::options ops{};
    ops.x86.disable_thread_safe = true;
    auto tp = fasttp::tracepoint{fasttp::addr_location{fib}, fasttp::make_handler(std::function{handler}), ops};
    fib(20);
    return 0;
}