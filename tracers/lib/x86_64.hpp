#ifndef DYNTRACE_TRACERS_LIB_X86_64_HPP_
#define DYNTRACE_TRACERS_LIB_X86_64_HPP_

namespace dyntrace::tracer
{
    class regs
    {



    public:
        using uint = uintptr_t;

        uint rsp;
        uint rbp;
        uint rax;
        uint rbx;
        uint rcx;
        uint rdx;
        uint rdi;
        uint rsi;
        uint r8;
        uint r9;
        uint r10;
        uint r11;
        uint r12;
        uint r13;
        uint r14;
        uint r15;
        uint rflags;

    private:
        template<size_t N>
        struct arg_idx{};

        constexpr uint arg(arg_idx<0>) const noexcept
        {
            return rdi;
        }
        constexpr uint arg(arg_idx<1>) const noexcept
        {
            return rsi;
        }
        constexpr uint arg(arg_idx<2>) const noexcept
        {
            return rdx;
        }
        constexpr uint arg(arg_idx<3>) const noexcept
        {
            return rcx;
        }
        constexpr uint arg(arg_idx<4>) const noexcept
        {
            return r8;
        }
        constexpr uint arg(arg_idx<5>) const noexcept
        {
            return r9;
        }
        template<size_t N>
        constexpr std::enable_if_t<(N > 5), uint> arg(arg_idx<N>) const noexcept
        {
            auto st = reinterpret_cast<uint*>(stack());
            return *(st + (N - 5) + 2);
        };

    public:

        template<size_t N>
        constexpr uint arg() const noexcept
        {
            return arg(arg_idx<N>{});
        }

        constexpr uint ret() const noexcept
        {
            return rax;
        }

        constexpr uint return_address() const noexcept
        {
            auto st = reinterpret_cast<uint*>(stack());
            return *(st + 1);
        }

        constexpr uint stack() const noexcept
        {
            return rsp;
        }
    };
}

#endif