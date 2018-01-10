
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
            auto addr = fasttp::symbol_location{"do_inc"}.resolve(*proc);
            addr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) + 7);
            auto tp = ctx.create(fasttp::addr_location{addr}, fasttp::handler{handler},
            fasttp::common{.x86.trap_handler = fasttp::handler{trap}});
            sleep(3);
            printf("Remove\n");
    }

    static void handler(const void* from, const dyntrace::arch::regs& regs)
    {
        using dyntrace::arch::arg;
        printf("Handler for %p rcx=%lu\n", from, regs.rcx);
    }

    static void trap(const void* from, const dyntrace::arch::regs& regs)
    {
        printf("Trap\n");
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