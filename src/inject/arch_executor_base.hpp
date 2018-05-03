#ifndef DYNTRACE_INJECT_ARCH_EXECUTOR_BASE_HPP_
#define DYNTRACE_INJECT_ARCH_EXECUTOR_BASE_HPP_

#include "dyntrace/inject/common.hpp"
#include "dyntrace/inject/ptrace.hpp"

namespace dyntrace::inject
{
    class arch_executor_base
    {
    public:
        arch_executor_base(process_ptr proc, void* execute, size_t execute_size);
        virtual ~arch_executor_base();

        uintptr_t remote_call(remote_ptr func, const remote_args& args);

        ptrace& get_ptrace()
        {
            return _pt;
        }

    protected:
        virtual void set_args(remote_ptr func, const remote_args& args, user_regs& regs) = 0;
        virtual uintptr_t get_ret(const user_regs& regs) = 0;

        remote_ptr code() const
        {
            return _code_ptr;
        }

    private:
        ptrace _pt;
        remote_ptr _code_ptr;
        user_regs _old_regs;
        std::vector<uint8_t> _old_code;
    };
}

#endif