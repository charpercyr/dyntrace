#ifndef DYNTRACE_FASTTP_ARCH_X86_64_JMP_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_JMP_HPP_

#include <cstdint>
#include <limits>
#include <optional>

namespace dyntrace::fasttp
{
    inline std::optional<int32_t> calc_jmp(uintptr_t from, uintptr_t to, uint8_t insn_size = 5) noexcept
    {
        from += insn_size;
        auto diff = static_cast<int64_t>(to) - static_cast<int64_t>(from);
        if(diff < std::numeric_limits<int32_t>::min() || diff > std::numeric_limits<int32_t>::max())
            return std::nullopt;
        return static_cast<int32_t>(diff);
    }
}

#endif