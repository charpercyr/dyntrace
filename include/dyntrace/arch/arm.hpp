#ifndef DYNTRACE_ARCH_ARM_HPP_
#define DYNTRACE_ARCH_ARM_HPP_

#include <cstddef>
#include <cstdint>

namespace dyntrace::arch
{
    struct __attribute__((packed)) regs
    {
        using uint = uintptr_t;

        uint arg(size_t i) const
        {
            return 0;
        }

        uint ret() const
        {
            return 0;
        }

        uint return_address() const
        {
            return 0;
        }

        uint stack() const
        {
            return 0;
        }
    };
}

#endif