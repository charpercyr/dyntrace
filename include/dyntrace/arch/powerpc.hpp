#ifndef DYNTRACE_ARCH_POWERPC_HPP_
#define DYNTRACE_ARCH_POWERPC_HPP_

namespace dyntrace::arch
{
    struct [[gnu::packed]] regs
    {
        using uint = unsigned long;

        uint ctr;
        uint cr;
        uint gpr[32];
        uint lr;

        uint arg(uint i) const noexcept
        {
            if(i <= 7)
                return gpr[i + 3];
            else
                return *(reinterpret_cast<uint*>(gpr[1]) + i - 7);
        }

        uint ret() const noexcept
        {
            return gpr[3];
        }

        uint return_address() const noexcept
        {
            return lr;
        }

        uint stack() const noexcept
        {
            return gpr[1];
        }
    };
}

#endif