
#include <atomic>
#include <cstdio>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <process/process.hpp>
#include <tracer.hpp>

#include <capstone.h>

#include "arch/asm.hpp"
#include "code_allocator.hpp"

using namespace dyntrace;

void hexdump(void* _data, size_t size)
{
    auto data = reinterpret_cast<char*>(_data);
    for(size_t i = 0; i < size;)
    {
        printf("%p: ", data + i);
        for(size_t j = 0; j < 16 && i < size; ++i, ++j)
        {
            printf("%.2x ", static_cast<uint32_t>(data[i]) & 0xff);
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


    size_t bytes_to_copy(void* _code)
    {
        csh handle;
        cs_open(CS_ARCH_X86, CS_MODE_64, &handle);

        auto code = reinterpret_cast<const uint8_t*>(_code);
        size_t size = 15;
        auto addr = reinterpret_cast<uintptr_t>(_code);
        size_t res = 0;

        cs_insn *insn = cs_malloc(handle);

        while(cs_disasm_iter(handle, &code, &size, &addr, insn) && res < 5)
        {
            res += insn->size;
            size = 15;
        }
        cs_free(insn, 1);
        return res;
    }

    void run()
    {
        try
        {
            namespace target = loader::target;
            using code_allocator = loader::code_allocator<target::code_size>;

            process::process proc{getpid()};
            auto sym = proc.get("do_loop_on");

            code_allocator alloc{proc};

            auto addr = alloc.alloc(make_address_range(sym.value, 2_G - 5));
            auto to_copy = bytes_to_copy(reinterpret_cast<void*>(sym.value));

            target::asm_printer printer{addr, sym.value};

            printer.save_state();
            printer.call_handler(reinterpret_cast<uintptr_t>(handler));
            printer.restore_state();
            printer.write(reinterpret_cast<void*>(sym.value), to_copy);
            printer.jmp_back(to_copy);

            mprotect(reinterpret_cast<void*>(sym.value & PAGE_MASK), PAGE_SIZE, PROT_WRITE | PROT_EXEC | PROT_READ);
            printer = target::asm_printer(reinterpret_cast<void*>(sym.value), reinterpret_cast<uintptr_t>(addr));
            printer.jmp_back(0);
        }
        catch(const std::exception& e)
        {
            fprintf(stderr, "Error: %s\n", e.what());
        }
    }

    static void handler(void* from, const dyntrace::tracer::regs& regs)
    {
        using namespace dyntrace::tracer;
        static size_t n{0};
        ++n;
        if(n == 0x100000)
        {
            printf("Hello from %p, a0->%ld a1->%ld\n", from, arg<0>(regs), arg<1>(regs));
            n = 0;
        }
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