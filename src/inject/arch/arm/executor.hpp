#ifndef DYNTRACE_INJECT_ARCH_ARM_HPP_
#define DYNTRACE_INJECT_ARCH_ARM_HPP_

#include "dyntrace/inject/common.hpp"
#include "dyntrace/inject/ptrace.hpp"

#include "dyntrace/process/process.hpp"

namespace dyntrace::inject
{
    class arch_executor
    {
    public:

        arch_executor(process_ptr proc);
        ~arch_executor();

        uintptr_t remote_call(remote_ptr func, const remote_args& args);

        ptrace& get_ptrace()
        {
            return _pt;
        }

        const ptrace& get_ptrace() const
        {
            return _pt;
        }

    private:
        ptrace _pt;
        user_regs _old_regs;
        remote_ptr _old_code_ptr;
        std::vector<uint8_t> _old_code;
    };
}

#endif