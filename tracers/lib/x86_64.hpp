#ifndef DYNTRACE_TRACERS_LIB_X86_64_HPP_
#define DYNTRACE_TRACERS_LIB_X86_64_HPP_

#include <cstdint>
#include <cstddef>
#include <type_traits>

namespace dyntrace::tracer
{
    class regs
    {
    public:
        using uint = uintptr_t;

        uint rax;
        uint rdi;
        uint rsi;
        uint rdx;
        uint rcx;
        uint r8;
        uint r9;
        uint rbx;
        uint r10;
        uint r11;
        uint r12;
        uint r13;
        uint r14;
        uint r15;
        uint rflags;
        uint rbp;
        uint rsp;

    private:
        template<size_t N>
        struct arg_idx{};

        uint arg(arg_idx<0>) const noexcept
        {
            return rdi;
        }
        uint arg(arg_idx<1>) const noexcept
        {
            return rsi;
        }
        uint arg(arg_idx<2>) const noexcept
        {
            return rdx;
        }
        uint arg(arg_idx<3>) const noexcept
        {
            return rcx;
        }
        uint arg(arg_idx<4>) const noexcept
        {
            return r8;
        }
        uint arg(arg_idx<5>) const noexcept
        {
            return r9;
        }
        template<size_t N>
        std::enable_if_t<(N > 5), uint> arg(arg_idx<N>) const noexcept
        {
            auto st = reinterpret_cast<uint*>(stack());
            return *(st + (N - 5) + 1);
        };

    public:

        template<size_t N>
        uint arg() const noexcept
        {
            return arg(arg_idx<N>{});
        }

        uint ret() const noexcept
        {
            return rax;
        }

        uint return_address() const noexcept
        {
            return *reinterpret_cast<uint*>(stack());
        }

        uint stack() const noexcept
        {
            return rsp;
        }
    };
}

#endif