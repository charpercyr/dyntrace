
#include <atomic>

#include <fasttp/fasttp.hpp>
#include <process/process.hpp>

using namespace dyntrace;

class loader_main
{
public:
    loader_main()
    {
        pthread_create(&_th, nullptr, _run, reinterpret_cast<void*>(this));
    }
    ~loader_main()
    {
        _done = true;
        pthread_join(_th, nullptr);
    }

private:

    static void* _run(void* self)
    {
        reinterpret_cast<loader_main*>(self)->run();
        return nullptr;
    }

    void run()
    {
            auto proc = std::make_shared<process::process>(getpid());
            auto ctx = fasttp::context{proc};
            printf("Insert\n");
            auto tp = ctx.create(fasttp::symbol_location{"do_inc"}, fasttp::handler{handler});
            sleep(3);
            printf("Remove\n");
    }

    static void handler(const void* from, const dyntrace::arch::regs& regs)
    {
        using dyntrace::arch::arg;
        printf("Handler for %p a0=%lld(%p)\n", from, *arg<long long*>(regs, 0), arg<void*>(regs, 0));
    }

    pthread_t _th{0};
    std::atomic<bool> _done{false};
};

namespace
{
    loader_main* loader;
}

void __attribute__((constructor)) init()
{
    loader = new loader_main;
}

void __attribute__((destructor)) fini()
{
    delete loader;
}