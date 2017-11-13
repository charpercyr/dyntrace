
#include <atomic>
#include <cstdio>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <process/process.hpp>

#include "arch/asm.hpp"
#include "code_allocator.hpp"

using namespace dyntrace;

void hexdump(void* _data, size_t size)
{
    auto data = reinterpret_cast<char*>(_data);
    for(size_t i = 0; i < size;)
    {
        printf("%.4lx: ", i);
        for(size_t j = 0; j < 16 && i < size; ++i, ++j)
        {
            printf("%x ", static_cast<uint32_t>(data[i]) & 0xff);
        }
        printf("\n");
    }
}

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
            process::process proc{getpid()};
            auto sym = proc.get("do_loop").value;
            auto alloc = loader::code_allocator<loader::target::x86_64::code_size>{proc};
            auto ptr = alloc.alloc(make_range<uintptr_t>(sym, 2_G - 5));
            printf("%p\n", ptr);
            alloc.free(ptr);
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