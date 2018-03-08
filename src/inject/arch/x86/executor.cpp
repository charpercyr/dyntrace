#include "executor.hpp"

#include "dyntrace/inject/error.hpp"

extern "C" void __remote_execute64();
extern const size_t __remote_execute64_size;

using namespace dyntrace::inject;

void dump_regs(const user_regs_struct& regs, FILE* out = stdout)
{
#define DUMP_ONE(name) fprintf(out, #name" %llx\n", regs.name)
    DUMP_ONE(rax);
    DUMP_ONE(rbx);
    DUMP_ONE(rcx);
    DUMP_ONE(rdx);
    DUMP_ONE(rdi);
    DUMP_ONE(rsi);
    DUMP_ONE(r8);
    DUMP_ONE(r9);
    DUMP_ONE(r10);
    DUMP_ONE(r11);
    DUMP_ONE(r12);
    DUMP_ONE(r13);
    DUMP_ONE(r14);
    DUMP_ONE(r15);
    DUMP_ONE(rbp);
    DUMP_ONE(rsp);
    DUMP_ONE(rip);
#undef DUMP_ONE
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
                if(flag(z.perms, process::permissions::exec) && z.size() >= __remote_execute64_size)
                {
                    _old_code_ptr = remote_ptr{z.start};
                    _old_code.resize(__remote_execute64_size);
                    _pt.read(
                        _old_code.data(),
                        _old_code_ptr,
                        __remote_execute64_size
                    );
                    _pt.write(
                        _old_code_ptr,
                        reinterpret_cast<void*>(__remote_execute64),
                        __remote_execute64_size
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
    _pt.write(_old_code_ptr, _old_code.data(), __remote_execute64_size);
    _pt.set_regs(_old_regs);
}

uintptr_t arch_executor::remote_call(remote_ptr func, const remote_args &args)
{
    using namespace std::string_literals;

    auto regs = _old_regs;
    regs.rax = func.as_int();
    regs.rdi = args[0];
    regs.rsi = args[1];
    regs.rdx = args[2];
    regs.rcx = args[3];
    regs.r8 = args[4];
    regs.r9 = args[5];
    regs.rip = _old_code_ptr.as_int();

    _pt.set_regs(regs);

    _pt.cont();

    int status = _pt.wait();
    // printf("=== Calling %p ===\n", func.as_ptr());
    if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
    {
        // dump_regs(_pt.get_regs(), stderr);
        throw inject_error{"Invalid signal received "s + strsignal(WSTOPSIG(status))};
    }
    // dump_regs(_pt.get_regs());

    return _pt.get_regs().rax;
}