#include <cstdio>
#include <fasttp/fasttp.hpp>
#include <thread>

using namespace dyntrace;

extern "C" void foo(int a, int b)
{
    printf("Foo     a=%d b=%d\n", a, b);
}

void handler(const void*, const tracer::regs& regs)
{
    using tracer::arg;
    printf("Handler a=%d b=%d\n", arg<0, int>(regs), arg<1, int>(regs));
}

void do_run()
{
    for(int i = 0; i < 5; ++i)
    {
        foo(i, i*i);
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(100ms);
    }
}

int main()
{
    do_run();
    printf("===========\n");

    auto proc = std::make_shared<process::process>(getpid());
    auto ctx = fasttp::context{proc};
    auto tp = ctx.create(fasttp::addr_location{foo}, fasttp::handler{handler});

    do_run();
    return 0;
}