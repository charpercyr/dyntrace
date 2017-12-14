#ifndef DYNTRACE_FASTTP_ARCH_X86_64_TRAP_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_TRAP_HPP_

#include <fasttp/code_ptr.hpp>

namespace dyntrace::fasttp
{
    struct trap_redirect_handle;

    trap_redirect_handle add_trap_redirect(code_ptr at, code_ptr redirect) noexcept;
    void remove_trap_redirect(code_ptr at) noexcept;

    struct trap_redirect_handle
    {
        explicit trap_redirect_handle(code_ptr _at = {})
            : at{_at} {}
        explicit trap_redirect_handle(trap_redirect_handle&& h)
            : at{h.at}
        {
            h.at = nullptr;
        }
        trap_redirect_handle& operator=(trap_redirect_handle&& h)
        {
            if(at) remove_trap_redirect(at);
            at = h.at;
            h.at = nullptr;
            return *this;
        }
        ~trap_redirect_handle()
        {
            if(at) remove_trap_redirect(at);
        }
        code_ptr at;
    };
}

#endif