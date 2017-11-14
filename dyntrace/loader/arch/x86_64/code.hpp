#ifndef DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_CODE_HPP_
#define DYNTRACE_DYNTRACE_LOADER_ARCH_X86_64_CODE_HPP_

#include <cstddef>
#include <cstdint>

namespace dyntrace::loader::target::code
{
    constexpr uint8_t save_state[] = {
        0x54,               // push %rsp
        0x41, 0x57,         // push %r15
        0x41, 0x56,         // push %r14
        0x41, 0x55,         // push %r13
        0x41, 0x54,         // push %r12
        0x41, 0x53,         // push %r11
        0x41, 0x52,         // push %r10
        0x41, 0x51,         // push %r9
        0x41, 0x50,         // push %r8
        0x56,               // push %rsi
        0x57,               // push %rdi
        0x52,               // push %rdx
        0x51,               // push %rcx
        0x53,               // push %rbx
        0x50,               // push %rax
        0x55,               // push %rbp
        0x9c,               // pushf
    };
    constexpr uint8_t restore_state[] = {
        0x9d,               // popf
        0x5d,               // pop %rbp
        0x58,               // pop %rax
        0x5b,               // pop %rbx
        0x59,               // pop %rcx
        0x5a,               // pop %rdx
        0x5f,               // pop %rdi
        0x5e,               // pop %rsi
        0x41, 0x58,         // pop %r8
        0x41, 0x59,         // pop %r9
        0x41, 0x5a,         // pop %r10
        0x41, 0x5b,         // pop %r11
        0x41, 0x5c,         // pop %r12
        0x41, 0x5d,         // pop %r13
        0x41, 0x5e,         // pop %r14
        0x41, 0x5f,         // pop %r15
        0x5c,               // pop %rsp
    };

    constexpr uint8_t call_handler[] = {
        // movabs $0xcafebabedeadbeef, %rdi
        0x48, 0xbf, 0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca,
        // movabs $0xcafebabedeadbeef, %rax
        0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca,
        0x48, 0x89, 0xe6,   // mov %rsi, %rsi
        0xff, 0xd0,         // call *%rax
    };
    constexpr size_t from_idx = 2;
    constexpr size_t handle_idx = 12;

    constexpr uint8_t jmp_back[] = {
        // jmp 0xdeadbabe
        0xe9, 0xbe, 0xba, 0xad, 0xde,
    };
    constexpr size_t to_idx = 1;
}

#endif