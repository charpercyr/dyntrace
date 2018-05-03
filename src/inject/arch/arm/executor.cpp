#include "executor.hpp"

#include "dyntrace/inject/error.hpp"

#include <cinttypes>

using namespace dyntrace::inject;

extern "C" void __remote_execute();
extern const size_t __remote_execute_size;

arch_executor::arch_executor(process_ptr proc)
    : arch_executor_base{std::move(proc), reinterpret_cast<void*>(__remote_execute), __remote_execute_size}
{

}

void arch_executor::set_args(remote_ptr func, const remote_args& args, user_regs& regs)
{
    regs.uregs[6] = func.as_int();
    regs.uregs[0] = args[0];
    regs.uregs[1] = args[1];
    regs.uregs[2] = args[2];
    regs.uregs[3] = args[3];
    regs.uregs[4] = args[4];
    regs.uregs[5] = args[5];
    regs.uregs[15] = code().as_int();
}

uintptr_t arch_executor::get_ret(const user_regs& regs)
{
    return regs.uregs[0];
}