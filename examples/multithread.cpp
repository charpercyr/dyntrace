
#include <dyntrace/fasttp/fasttp.hpp>

#include <atomic>
#include <mutex>
#include <signal.h>
#include <thread>

class spinlock
{
public:

    void lock()
    {
        while(_lock.test_and_set(std::memory_order_acquire));
    }

    void unlock()
    {
        _lock.clear(std::memory_order_release);
    }

private:
    std::atomic_flag _lock;
} call_count_lock;
unsigned long long call_count{0};

void __attribute__((noinline)) nothing()
{
    asm volatile("":::"memory");
}


void worker()
{
    for(;;) nothing();
}

#define N_THREADS 4

using namespace dyntrace;

int main()
{
    using namespace std::chrono_literals;
    auto handler = [](const void*, const arch::regs&)
    {
        std::unique_lock lock{call_count_lock};
        ++call_count;
    };
    fasttp::tracepoint tp{fasttp::resolve(nothing), fasttp::point_handler{handler}};
    std::thread ths[N_THREADS];
    for(int i = 0; i < N_THREADS; ++i)
        ths[i] = std::thread{worker};
    for(;;)
    {
        std::this_thread::sleep_for(1s);
        printf("Call count: %llu\n", call_count);
    }
    return 0;
}