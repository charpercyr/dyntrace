
#include <atomic>

#include <process/process.hpp>
#include <tracer.hpp>

#include <fasttp/fasttp.hpp>

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
        try
        {
            auto proc = std::make_shared<process::process>(getpid());
            fasttp::context ctx{proc};
            printf("Insert\n");
            auto tp = ctx.create(fasttp::symbol_location{"do_inc"}, fasttp::handler{handler});
            sleep(3);
            printf("Remove\n");
        }
        catch(const std::exception& e)
        {
            fprintf(stderr, "Error: %s\n", e.what());
        }
    }

    static void handler(const void* from, const dyntrace::tracer::regs& regs)
    {
        using dyntrace::tracer::arg;
        printf("Handler for %p a0=%lld(%p)\n", from, *arg<0, long long*>(regs), arg<0, void*>(regs));
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