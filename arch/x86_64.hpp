#ifndef DYNTRACE_ARCH_X86_64_HPP_
#define DYNTRACE_ARCH_X86_64_HPP_

#include <cstdint>
#include <cstddef>
#include <type_traits>

namespace dyntrace::arch
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
    public:

        uint arg(size_t i) const noexcept
        {
            switch(i)
            {
            case 0:
                return rdi;
            case 1:
                return rsi;
            case 2:
                return rdx;
            case 3:
                return rcx;
            case 4:
                return r8;
            case 5:
                return r9;
            default:
                return *(reinterpret_cast<uint*>(rsp) + i - 4);
            }
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