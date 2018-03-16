#include "executor.hpp"

#include "dyntrace/inject/error.hpp"

#include <cinttypes>


#ifdef __i386__
extern "C" void __remote_execute32();
extern const size_t __remote_execute32_size;
#define __remote_execute __remote_execute32
#define __remote_execute_size __remote_execute32_size
#else
extern "C" void __remote_execute64();
extern const size_t __remote_execute64_size;
#define __remote_execute __remote_execute64
#define __remote_execute_size __remote_execute64_size
#endif

using namespace dyntrace::inject;

#ifdef __i386__
#define REG(name) e##name
#else // __i386__
#define REG(name) r##name
#endif // __i386__

namespace
{
#ifdef _DEBUG
    void dump_regs(const user_regs_struct &regs, FILE *out = stdout)
    {
#ifdef __i386__
#define DUMP_ONE(name) fprintf(out, #name" %lx\n", regs.name)
#else // __i386__
#define DUMP_ONE(name) fprintf(out, #name" %llx\n", regs.name)
#endif // __i386__
        DUMP_ONE(REG(ax));
        DUMP_ONE(REG(bx));
        DUMP_ONE(REG(cx));
        DUMP_ONE(REG(dx));
        DUMP_ONE(REG(di));
        DUMP_ONE(REG(si));
#ifdef __x86_64__
        DUMP_ONE(r8);
        DUMP_ONE(r9);
        DUMP_ONE(r10);
        DUMP_ONE(r11);
        DUMP_ONE(r12);
        DUMP_ONE(r13);
        DUMP_ONE(r14);
        DUMP_ONE(r15);
#endif
        DUMP_ONE(REG(bp));
        DUMP_ONE(REG(sp));
        DUMP_ONE(REG(ip));
#undef DUMP_ONE
    }
#endif // _DEBUG
}

arch_executor::arch_executor(process_ptr proc)
    : _pt{proc->pid()}
{
    const std::string this_process = get_executable(proc->pid());
    _old_regs = _pt.get_regs();
    auto memmap = proc->create_memmap();
    for(auto&& b : memmap.binaries())
    {
        if(b.second.name() == this_process)
        {
            for(auto&& z : b.second.zones())
            {
                if(flag(z.perms, process::permissions::exec) && z.size() >= __remote_execute_size)
                {
                    _old_code_ptr = remote_ptr{z.start};
                    _old_code.resize(__remote_execute_size);
                    _pt.read(
                        _old_code.data(),
                        _old_code_ptr,
                        __remote_execute_size
                    );
                    _pt.write(
                        _old_code_ptr,
                        reinterpret_cast<void*>(__remote_execute),
                        __remote_execute_size
                    );
                    return;
                }
            }
        }
    }
    throw inject_error{"Could not find executable zone"};
}

arch_executor::~arch_executor()
{
    _pt.write(_old_code_ptr, _old_code.data(), __remote_execute_size);
    _pt.set_regs(_old_regs);
}

uintptr_t arch_executor::remote_call(remote_ptr func, const remote_args &args)
{
    using namespace std::string_literals;

    auto regs = _old_regs;
    regs.REG(ax) = func.as_int();
    regs.REG(di) = args[0];
    regs.REG(si) = args[1];
    regs.REG(dx) = args[2];
    regs.REG(cx) = args[3];
#ifdef __i386__
    regs.ebx = args[4];
    regs.ebp = args[5];
#else // __i386__
    regs.r8 = args[4];
    regs.r9 = args[5];
#endif // __i386__
    regs.REG(ip) = _old_code_ptr.as_int();

    _pt.set_regs(regs);
    _pt.cont();

    int status = _pt.wait();
    if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
    {
#ifdef _DEBUG
        dump_regs(regs, stderr);
#endif // _DEBUG
        throw inject_error{"Invalid signal received "s + strsignal(WSTOPSIG(status))};
    }

    return _pt.get_regs().REG(ax);
}