
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
                auto tp = context.create("do_loop", fasttp::handler{handler});
                sleep(10);
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
        printf("Handler for %p %d\n", from, arg<0, int>(regs));
    }

    pthread_t _th;
    std::atomic<bool> _done{false};
};

namespace
{
    std::unique_ptr<loader_main> l;
}

void __attribute__((constructor)) init()
{
    l = std::make_unique<loader_main>();
}

void __attribute__((destructor)) fini()
{
    l = nullptr;
}