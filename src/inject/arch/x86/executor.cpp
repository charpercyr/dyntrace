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

arch_executor::arch_executor(process_ptr proc)
    : arch_executor_base{std::move(proc), reinterpret_cast<void*>(__remote_execute), __remote_execute_size}
{

}

void arch_executor::set_args(remote_ptr func, const remote_args& args, user_regs& regs)
{
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
    regs.REG(ip) = code().as_int();
}

uintptr_t arch_executor::get_ret(const user_regs& regs)
{
    return regs.REG(ax);
}