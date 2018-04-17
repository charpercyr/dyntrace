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

        arch_executor(process_ptr proc)
            : _pt{proc->pid()}
        {

        }

        uintptr_t remote_call(remote_ptr func, const remote_args& args)
        {
            return 0;
        }

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
    };
}

#endif