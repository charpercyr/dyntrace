#ifndef DYNTRACE_INJECT_ARCH_POWERPC_EXECUTOR_HPP_
#define DYNTRACE_INJECT_ARCH_POWERPC_EXECUTOR_HPP_

#include <cstddef>

#include "dyntrace/inject/common.hpp"
#include "dyntrace/inject/ptrace.hpp"

#include "dyntrace/process/process.hpp"

#include "../../arch_executor_base.hpp"

namespace dyntrace::inject
{
    class arch_executor : public arch_executor_base
    {
    public:

        arch_executor(process_ptr proc)
            : arch_executor_base{std::move(proc), nullptr, 0} {}
        ~arch_executor() override = default;

    protected:
        void set_args(remote_ptr func, const remote_args& args, user_regs& regs) override {}
        uintptr_t get_ret(const user_regs& regs) override
        {
            return 0;
        }
    };
}

#endif