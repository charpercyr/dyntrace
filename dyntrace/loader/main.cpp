
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
            fasttp::context context{proc};
            {
                printf("Insert\n");
                auto tp = context.create(fasttp::symbol_location{"do_loop"}, fasttp::handler{handler});
                sleep(3);
                printf("Remove\n");
            }
        }
        catch(const std::exception& e)
        {
            fprintf(stderr, "Error: %s\n", e.what());
        }
    }

    static void handler(void* from, const dyntrace::tracer::regs& regs)
    {
        using dyntrace::tracer::arg;
        printf("Handler for %p %s\n", from, arg<0, char*>(regs));
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