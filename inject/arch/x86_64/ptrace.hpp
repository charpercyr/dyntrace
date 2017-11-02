#ifndef DYNTRACE_INJECT_ARCH_X86_64_PTRACE_HPP_
#define DYNTRACE_INJECT_ARCH_X86_64_PTRACE_HPP_

#include <inject/remote_util.hpp>

#include <cstdint>
#include <vector>

#include <sys/user.h>

namespace dyntrace
{
    namespace inject
    {

        class x86_64
        {
        public:
            explicit x86_64(ptrace<x86_64>& pt) noexcept
                : _pt{pt} {}
            using regval = uint64_t;
            using regs = user_regs_struct;

            regval remote_call(remote_ptr<x86_64> ptr, const regs& r);

            void prepare();
            void cleanup();
        private:
            ptrace<x86_64>& _pt;
            remote_ptr<x86_64> _func_ptr;
            std::vector<char> _old_func;
        };
    }
}

#endif