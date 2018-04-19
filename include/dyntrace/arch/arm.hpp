#ifndef DYNTRACE_ARCH_ARM_HPP_
#define DYNTRACE_ARCH_ARM_HPP_

#include <cstddef>
#include <cstdint>

/*
 * 00: sp/r13
 * 04: r0
 * 08: r1
 * 0c: r2
 * 10: r3
 * 14: r4
 * 18: r5
 * 1c: r6
 * 20: r7
 * 24: r8
 * 28: r9
 * 2c: sl/r10
 * 30: sp/r11
 * 34: ip/r12
 * 38: lr/r14
 * 3c: reserved
 *
 * Size: 0x40
 */

namespace dyntrace::arch
{
    struct __attribute__((packed)) regs
    {
        using uint = unsigned long;

        union{uint sp, r13;};
        uint r0;
        uint r1;
        uint r2;
        uint r3;
        uint r4;
        uint r5;
        uint r6;
        uint r7;
        uint r8;
        uint r9;
        union{uint sl, r10;};
        union{uint fp, r11;};
        union{uint ip, r12;};
        union{uint lr, r14;};

        uint arg(size_t i) const
        {
            switch(i)
            {
            case 0:
                return r0;
            case 1:
                return r1;
            case 2:
                return r2;
            case 3:
                return r3;
            default:
                return *reinterpret_cast<uint*>(stack() + i - 4);
            }
        }

        uint ret() const
        {
            return r0;
        }

        uint return_address() const
        {
            return lr;
        }

        uint stack() const
        {
            return sp;
        }
    };
}

#endif