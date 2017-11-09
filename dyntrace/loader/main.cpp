
#include <atomic>
#include <cstdio>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <process/process.hpp>

#include "asm.hpp"

using namespace dyntrace::process;

class loader
{
public:
    loader()
    {
        pthread_create(&_th, nullptr, _run, reinterpret_cast<void*>(this));
    }
    ~loader()
    {
        _done = true;
        pthread_join(_th, nullptr);
    }

private:

    static void* _run(void* self)
    {
        reinterpret_cast<loader*>(self)->run();
        return nullptr;
    }

    void run()
    {
        try
        {
            process proc{getpid()};
            auto sym = proc.get("do_loop").value;
            void *code_loc = mmap(reinterpret_cast<void*>(sym), PAGE_SIZE,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            auto code = dyntrace::loader::print_handler(sym, reinterpret_cast<uintptr_t>(code_loc), reinterpret_cast<uintptr_t>(handler));
            printf("%lx %p %lu\n", sym, code_loc, code.size());
            memcpy(code_loc, code.data(), code.size());
        }
        catch(const std::exception& e)
        {
            fprintf(stderr, "Error: %s\n", e.what());
        }
    }

    static void handler()
    {

    }

    pthread_t _th;
    std::atomic<bool> _done{false};
};

namespace
{
    std::unique_ptr<loader> l;
}

void __attribute__((constructor)) init()
{
    l = std::make_unique<loader>();
}

void __attribute__((destructor)) fini()
{
    l = nullptr;
}