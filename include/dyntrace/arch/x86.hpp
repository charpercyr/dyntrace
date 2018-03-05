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
    struct __attribute__((packed)) regs
    {
        using uint = uintptr_t;

        uint ax;
        uint di;
        uint si;
        uint dx;
        uint cx;
#ifdef __x86_64__
        uint r8;
        uint r9;
#endif // __x86_64__
        uint bx;
#ifdef __x86_64__
        uint r10;
        uint r11;
        uint r12;
        uint r13;
        uint r14;
        uint r15;
#endif // __x86_64__
        uint bp;
        uint flags;
        uint sp;

#ifdef __x86_64__
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
                return di;
            case 1:
                return si;
            case 2:
                return dx;
            case 3:
                return cx;
            case 4:
                return r8;
            case 5:
                return r9;
            default:
                return *(reinterpret_cast<uint*>(sp) + i - 4);
            }
        }
#else // __x86_64__
        uint arg(size_t i) const noexcept
        {
            return *(reinterpret_cast<uint*>(sp) + i);
        }
#endif // __x86_64__

        uint ret() const noexcept
        {
            return ax;
        }

        uint return_address() const noexcept
        {
            // A call pushes the return address on the stack.
            return *reinterpret_cast<uint*>(stack());
        }

        uint stack() const noexcept
        {
            return sp;
        }
    };
}

#endif