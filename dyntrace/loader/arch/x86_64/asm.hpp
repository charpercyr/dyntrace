#ifndef DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_ASM_HPP_
#define DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_ASM_HPP_

#include "code.hpp"

#include <limits>

namespace dyntrace::loader::target
{

    struct x86_64
    {
        static constexpr uintptr_t max_branch_distance = std::numeric_limits<int32_t>::max() - 5;
        static constexpr size_t branch_size = 5;
        static constexpr size_t instruction_max_size = 15;
        // 19 is the limit for the number of bytes to execute out of line
        static constexpr size_t code_size =
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

        class regs
        {
            template<size_t N>
            struct arg_idx{};

            uintptr_t _arg(arg_idx<0>) const noexcept
            {
                return rdi;
            }
            uintptr_t _arg(arg_idx<1>) const noexcept
            {
                return rsi;
            }
            uintptr_t arg(arg_idx<2>) const noexcept
            {
                return rdx;
            }
            uintptr_t arg(arg_idx<3>) const noexcept
            {
                return rcx;
            }
            uintptr_t arg(arg_idx<4>) const noexcept
            {
                return r8;
            }
            uintptr_t arg(arg_idx<5>) const noexcept
            {
                return r9;
            }
        public:
            uintptr_t rsp;
            uintptr_t rbp;
            uintptr_t rax;
            uintptr_t rbx;
            uintptr_t rcx;
            uintptr_t rdx;
            uintptr_t rdi;
            uintptr_t rsi;
            uintptr_t r8;
            uintptr_t r9;
            uintptr_t r10;
            uintptr_t r11;
            uintptr_t r12;
            uintptr_t r13;
            uintptr_t r14;
            uintptr_t r15;

            template<size_t N>
            uintptr_t arg() const noexcept
            {
                return _arg(arg_idx<N>{});
            }

            uintptr_t ret() const noexcept
            {
                return rax;
            }

            uintptr_t stack() const noexcept
            {
                return rsp;
            }
        };
    };
}

#endif