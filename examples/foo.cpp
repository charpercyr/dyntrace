#include <cstdio>
#include <fasttp/fasttp.hpp>
#include <thread>

using namespace dyntrace;

extern "C" void __attribute__((noinline)) foo(int a, const std::string& b)
{
    printf("Foo a=%d b=%s\n", a, b.c_str());
}

void do_run()
{
    for(int i = 0; i < 5; ++i)
    {
        std::string str = "Hello-" + std::to_string(i*i);
        foo(i, str);
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(100ms);
    }
}

int main()
{
    do_run();

    auto handler = [](const void* caller, const tracer::regs& regs)
    {
        using tracer::arg;
        printf("Handler for %p a=%d b=%s\n",
               caller,
               arg<0, int>(regs),
               arg<1, const std::string&>(regs).c_str()
        );
    };

    auto proc = std::make_shared<process::process>(getpid());
    auto ctx = fasttp::context{proc};
    auto tp = ctx.create(
            fasttp::addr_location{foo},
            fasttp::handler{handler},
            fasttp::options::disable_basic_block | fasttp::options::disable_thread_safe
    );

    printf("===========\n");
    do_run();
    return 0;
}