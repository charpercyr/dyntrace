/**
 * x86_64 registers and accessors.
 */
#ifndef DYNTRACE_ARCH_X86_64_HPP_
#define DYNTRACE_ARCH_X86_64_HPP_

#include <cstdint>
#include <cstddef>
#include <type_traits>

namespace dyntrace::arch
{
    class __attribute__((packed)) regs
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
        uint rbp;
        uint rflags;
        uint rsp;

    private:
    public:

        uint arg(size_t i) const noexcept
        {
            /*
             * Arguments
             * 0: rdi
             * 1: rsi
             * 2: rdx
             * 3: rcx
             * 4: r8
             * 5: r9
             * 6-: stack
             */
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
            // A call pushes the return address on the stack.
            return *reinterpret_cast<uint*>(stack());
        }

        uint stack() const noexcept
        {
            return rsp;
        }
    };
}

#endif