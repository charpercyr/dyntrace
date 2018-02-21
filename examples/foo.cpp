#include "dyntrace/fasttp/common.hpp"
#include "dyntrace/fasttp/fasttp.hpp"

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
    {
        auto handler = [](const void *caller, int a, const std::string &b)
        {
            using arch::arg;
            printf("Handler for %p a=%d b=%s\n", caller, a, b.c_str());
        };

        fasttp::options ops{};
        ops.x86.disable_thread_safe = true;
        auto tp = fasttp::tracepoint{fasttp::addr_location{foo}, fasttp::make_handler(std::function{handler}), ops};
        printf("===========\n");
        do_run();
    }
    do_run();
    return 0;
}