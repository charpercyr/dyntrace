#ifndef DYNTRACE_INJECT_ARCH_X86_64_TARGET_HPP_
#define DYNTRACE_INJECT_ARCH_X86_64_TARGET_HPP_

#include <inject/remote_util.hpp>

#include <cstdint>
#include <vector>

#include <sys/user.h>

namespace dyntrace::inject::target
{
    struct x86_64
    {
        using regs = user_regs_struct;
        using regval = uintptr_t;

        static void set_args(regs& r, const remote_args<x86_64>& args, remote_ptr<x86_64> func, remote_ptr<x86_64> caller) noexcept;
        static regval get_return(const regs& r) noexcept;
        static void* remote_call_impl_ptr() noexcept;
        static size_t remote_call_impl_size() noexcept;

        static void* remote_dlopen_impl_ptr() noexcept;
        static size_t remote_dlopen_impl_size() noexcept;
        static void* remote_dlclose_impl_ptr() noexcept;
        static size_t remote_dlclose_impl_size() noexcept;
    };

}

#endif