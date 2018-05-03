#include "arch_executor_base.hpp"

#include "dyntrace/inject/error.hpp"

using namespace dyntrace::inject;

arch_executor_base::arch_executor_base(dyntrace::inject::process_ptr proc, void* execute, size_t execute_size)
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
                if(flag(z.perms, process::permissions::exec) && z.size() >= execute_size)
                {
                    _code_ptr = remote_ptr{z.start};
                    _old_code.resize(execute_size);
                    _pt.read(
                        _old_code.data(),
                        _code_ptr,
                        execute_size
                    );
                    _pt.write(
                        _code_ptr,
                        execute,
                        execute_size
                    );
                    return;
                }
            }
        }
    }
    throw inject_error{"Could not find executable zone"};
}

arch_executor_base::~arch_executor_base()
{
    _pt.write(_code_ptr, _old_code.data(), _old_code.size());
    _pt.set_regs(_old_regs);
}

uintptr_t arch_executor_base::remote_call(remote_ptr func, const remote_args& args)
{
    using namespace std::string_literals;
    auto regs = _old_regs;

    set_args(func, args, regs);

    _pt.set_regs(regs);
    _pt.cont();

    int status = _pt.wait();
    if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        throw inject_error{"Invalid signal received "s + strsignal(WSTOPSIG(status))};

    return get_ret(_pt.get_regs());
}