#include "dyntrace/fasttp/common.hpp"
#include "dyntrace/fasttp/fasttp.hpp"

#include <thread>

using namespace dyntrace;

extern "C" int __attribute__((noinline)) foo(int a, const std::string& b)
{
    printf("Foo a=%d b=%s\n", a, b.c_str());
    return a*a;
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
        auto enter_handler = [](const void *caller, const arch::regs& r)
        {
            using arch::arg;
            printf("Enter %p a=%d b=%s\n", caller, arg<int>(r, 0), arg<const std::string&>(r, 1).c_str());
        };
        auto exit_handler = [](const void* caller, const arch::regs& r)
        {
            using arch::ret;
            printf("Exit  %p r=%lu\n", caller, ret(r));
        };

        fasttp::options ops{};
        ops.x86.disable_thread_safe = true;
        auto tp = fasttp::tracepoint{fasttp::make_location(foo), fasttp::entry_exit_handler{enter_handler, exit_handler}, ops};
        printf("===========\n");
        do_run();
    }
    do_run();
    return 0;
}