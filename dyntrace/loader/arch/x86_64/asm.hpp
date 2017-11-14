#ifndef DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_ASM_HPP_
#define DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_ASM_HPP_

#include "code.hpp"

#include <limits>
#include <type_traits>

namespace dyntrace::loader::target
{
    constexpr uintptr_t max_branch_distance = std::numeric_limits<int32_t>::max() - 5;
    constexpr size_t branch_size = 5;
    constexpr size_t instruction_max_size = 15;
    // 19 is the limit for the number of bytes to execute out of line
    constexpr size_t code_size =
            sizeof(code::save_state) +
            sizeof(code::restore_state) +
            sizeof(code::call_handler) +
            sizeof(code::jmp_back) +
            branch_size - 1 + instruction_max_size;

    class asm_printer
    {
    public:
        asm_printer(void* to, uintptr_t from) noexcept
            : _to{reinterpret_cast<uint8_t*>(to)}, _from{from} {}

        void save_state();
        void restore_state();

        void call_handler(uintptr_t handler);
        void jmp_back(uintptr_t off);

        void write(void* code, size_t code_size);

    private:
        uint8_t* _to;
        uintptr_t _from;
    };
}

#endif