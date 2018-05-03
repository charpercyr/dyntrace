#ifndef DYNTRACE_INJECT_ARCH_ARM_HPP_
#define DYNTRACE_INJECT_ARCH_ARM_HPP_

#include "dyntrace/inject/common.hpp"
#include "dyntrace/inject/ptrace.hpp"

#include "dyntrace/process/process.hpp"

#include "../../arch_executor_base.hpp"

namespace dyntrace::inject
{
    class arch_executor : public arch_executor_base
    {
    public:

        arch_executor(process_ptr proc);
        ~arch_executor() override = default;

    protected:
        void set_args(remote_ptr func, const remote_args& args, user_regs& regs) override;
        uintptr_t get_ret(const user_regs& regs) override;
    };
}

#endif