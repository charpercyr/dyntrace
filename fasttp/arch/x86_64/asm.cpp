#include "asm.hpp"

#include <fasttp/error.hpp>
#include <util/util.hpp>

using namespace dyntrace::fasttp;

namespace
{
    uintptr_t cast(void* ptr) noexcept
    {
        return reinterpret_cast<uintptr_t>(ptr);
    }

    constexpr uint8_t call_handler[] = {
            // === Save state ===
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
            // === Call handler ===
            // movabs $0xcafebabedeadbeef, %rdi
            0x48, 0xbf, 0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca,
            // movabs $0xcafebabedeadbeef, %rax
            0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca,
            0x48, 0x89, 0xe6,   // mov %rsi, %rsi
            0xff, 0xd0,         // call *%rax
            // === Restore state ===
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
    constexpr size_t from_idx = 27;
    constexpr size_t handle_idx = 37;

    int32_t calc_jmp(uintptr_t from, uintptr_t to)
    {
        from += branch_size;
        intptr_t diff = static_cast<intptr_t>(to) - static_cast<intptr_t>(from);
        if(diff > std::numeric_limits<int32_t>::max() || diff < std::numeric_limits<int32_t>::min())
        {
            using dyntrace::to_hex_string;
            throw fasttp_error("Cannot jmp from 0x" + to_hex_string(from - branch_size) + " to 0x" + to_hex_string(to));
        }
        return static_cast<int32_t>(diff);
    }
}

void dyntrace::fasttp::safe_store(void *to, uintptr_t data)
{
    asm volatile("lock xchg %0, %1": "=m"(to), "=r"(data));
}

void dyntrace::fasttp::print_branch(void *target, void *to)
{
    static constexpr uint8_t jmp = 0xe9;

    uint8_t data[8];
    memcpy(data, target, 8);
    data[0] = jmp;
    auto diff = calc_jmp(cast(target), cast(to));
    memcpy(data + 1, &diff, 4);

    safe_store(target, *reinterpret_cast<uintptr_t*>(data));
}

code_allocator::unique_ptr dyntrace::fasttp::print_handler(code_allocator &alloc, void* func, void* ret, void* handler, const std::vector<uint8_t>& out_of_line)
{
    auto res = alloc.make_unique(
            make_address_range(cast(func), std::numeric_limits<int32_t>::max() - branch_size),
            sizeof(call_handler) + out_of_line.size() + branch_size
    );
    auto data = reinterpret_cast<uint8_t*>(res.get());

    memcpy(data, call_handler, sizeof(call_handler));
    memcpy(data + from_idx, &func, 8);
    memcpy(data + handle_idx, &handler, 8);
    memcpy(data + sizeof(call_handler), out_of_line.data(), out_of_line.size());
    print_branch(data + sizeof(call_handler) + out_of_line.size(), ret);

    return std::move(res);
}

csh dyntrace::fasttp::create_csh()
{
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    return handle;
}