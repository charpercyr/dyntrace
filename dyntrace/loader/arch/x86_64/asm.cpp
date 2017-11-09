#include <dyntrace/loader/asm.hpp>

#include <cstring>
#include <cmath>
#include <limits>

namespace
{

    void push_regs(std::vector<uint8_t>& v)
    {
        static const uint8_t data[] = {
            0x54,       // push %rsp
            0x55,       // push %rbp
            0x50,       // push %rax
            0x53,       // push %rbx
            0x51,       // push %rcx
            0x52,       // push %rdx
            0x57,       // push %rdi
            0x56,       // push %rsi
            0x41, 0x50, // push %r8
            0x41, 0x51, // push %r9
            0x41, 0x52, // push %r10
            0x41, 0x53, // push %r11
            0x41, 0x54, // push %r12
            0x41, 0x55, // push %r13
            0x41, 0x56, // push %r14
            0x41, 0x57  // push %r15
        };
        v.resize(v.size() + sizeof(data));
        memcpy((&v.back()) - sizeof(data), data, sizeof(data));
    }

    void pop_regs(std::vector<uint8_t>& v)
    {
        static const uint8_t data[] = {
            0x41, 0x5f, // pop %r15
            0x41, 0x5e, // pop %r14
            0x41, 0x5d, // pop %r13
            0x41, 0x5c, // pop %r12
            0x41, 0x5b, // pop %r11
            0x41, 0x5a, // pop %r10
            0x41, 0x59, // pop %r9
            0x41, 0x58, // pop %r8
            0x5e,       // pop %rsi
            0x5f,       // pop %rdi
            0x5a,       // pop %rdx
            0x59,       // pop %rcx
            0x5b,       // pop %rbx
            0x58,       // pop %rax
            0x5d,       // pop %rbp
            0x5c        // pop %rsp
        };
        v.resize(v.size() + sizeof(data));
        memcpy(&v.back() - sizeof(data), data, sizeof(data));
    }

    void movabs_to_rdi(std::vector<uint8_t>& v, uintptr_t value)
    {
        v.push_back(0x48);
        v.push_back(0xbf);
        v.resize(v.size() + 8);
        memcpy((&v.back()) - 8, &value, 8);
    }

    void movabs_to_rax(std::vector<uint8_t>& v, uintptr_t value)
    {
        v.push_back(0x48);
        v.push_back(0xb8);
        v.resize(v.size() + 8);
        memcpy((&v.back()) - 8, &value, 8);
    }

    void call(std::vector<uint8_t>& v)
    {
        // mov %rsp, %rsi
        v.push_back(0x48);
        v.push_back(0x89);
        v.push_back(0xe6);
        // call *%rax
        v.push_back(0xff);
        v.push_back(0xd0);
    }

    void jmp(std::vector<uint8_t>& v, uintptr_t from, uintptr_t to)
    {
        intptr_t diff = static_cast<intptr_t>(from) - static_cast<intptr_t>(to) + 5;
        if(std::abs(diff) > std::numeric_limits<int32_t>::max() || std::abs(diff) < std::numeric_limits<int32_t>::min())
        {
            return;
        }
        v.push_back(0xe9);
        v.resize(v.size() + 4);
        memcpy((&v.back()) - 4, &diff, 4);
    }
}

std::vector<uint8_t> dyntrace::loader::print_handler(uintptr_t from, uintptr_t to, uintptr_t handler)
{
    std::vector<uint8_t> res;

    push_regs(res);
    movabs_to_rdi(res, from);
    movabs_to_rax(res, handler);
    call(res);
    pop_regs(res);
    jmp(res, to + res.size(), from);

    return res;
}