#ifndef DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_ASM_HPP_
#define DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_ASM_HPP_

#include "code.hpp"

#include <limits>

namespace dyntrace::loader::target
{
    struct x86_64
    {
        static constexpr size_t code_size = code::code_size;
        static constexpr uintptr_t max_branch_distance = std::numeric_limits<int32_t>::max() - 5;

        void write_code(uintptr_t from, uintptr_t to, uintptr_t handler) const noexcept;
    };
}

#endif