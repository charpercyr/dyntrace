#include "executor.hpp"

#include "dyntrace/inject/error.hpp"

#include <cinttypes>

using namespace dyntrace::inject;

extern "C" void __remote_execute();
extern const size_t __remote_execute_size;


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

uintptr_t arch_executor::remote_call(remote_ptr func, const remote_args& args)
{
    using namespace std::string_literals;
    auto regs = _old_regs;

    regs.uregs[6] = func.as_int();
    regs.uregs[0] = args[0];
    regs.uregs[1] = args[1];
    regs.uregs[2] = args[2];
    regs.uregs[3] = args[3];
    regs.uregs[4] = args[4];
    regs.uregs[5] = args[5];
    regs.uregs[15] = _old_code_ptr.as_int();

    _pt.set_regs(regs);
    _pt.cont();

    int status = _pt.wait();
    if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
    {
        throw inject_error{"Invalid signal received "s + strsignal(WSTOPSIG(status))};
    }

    return _pt.get_regs().uregs[0];
}