#include "tracepoint.hpp"

namespace
{
    constexpr uint8_t handler_code[] = {
    /// Save urgent registers (rsp, rbp, rflags)
        /* 00: push %rsp                        */ 0x54,
        /* 01: push %rbp                        */ 0x55,
        /* 02: pushf                            */ 0x9c,
    /// Increment refcount
        /* 03: movabs &refcount, %rbp           */ 0x48, 0xbd, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        /* 0d: lock incq (%rbp)                 */ 0xf0, 0x48, 0xff, 0x45, 0x00,
    /// Save other registers
        /* 12: push %r15                        */ 0x41, 0x57,
        /* 14: push %r14                        */ 0x41, 0x56,
        /* 16: push %r13                        */ 0x41, 0x55,
        /* 18: push %r12                        */ 0x41, 0x54,
        /* 1a: push %r11                        */ 0x41, 0x53,
        /* 1c: push %r10                        */ 0x41, 0x52,
        /* 1e: push %rbx                        */ 0x53,
        /* 1f: push %r9                         */ 0x41, 0x51,
        /* 21: push %r8                         */ 0x41, 0x50,
        /* 23: push %rcx                        */ 0x51,
        /* 24: push %rdx                        */ 0x52,
        /* 25: push %rsi                        */ 0x56,
        /* 26: push %rdi                        */ 0x57,
        /* 27: push %rax                        */ 0x50,
    /// call handler(arch_tracepoint*, regs*)
        /* 28: movabs &tracepoint, %rdi         */ 0x48, 0xbf, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        /* 32: mov %rsp, %rsi                   */ 0x48, 0x89, 0xe6,
        /* 35: movabs &handler, %rax            */ 0x48, 0xb8, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba, 0xad, 0xde,
        /* 3f: callq *%rax                      */ 0xff, 0xd0,
    /// Restore other registers
        /* 41: pop %rax                         */ 0x58,
        /* 42: pop %rdi                         */ 0x5f,
        /* 43: pop %rsi                         */ 0x5e,
        /* 44: pop %rdx                         */ 0x5a,
        /* 45: pop %rcx                         */ 0x59,
        /* 46: pop %r8                          */ 0x41, 0x58,
        /* 48: pop %r9                          */ 0x41, 0x59,
        /* 4a: pop %rbx                         */ 0x5b,
        /* 4b: pop %r10                         */ 0x41, 0x5a,
        /* 4d: pop %r11                         */ 0x41, 0x5b,
        /* 4f: pop %r12                         */ 0x41, 0x5c,
        /* 51: pop %r13                         */ 0x41, 0x5d,
        /* 53: pop %r14                         */ 0x41, 0x5e,
        /* 55: pop %r15                         */ 0x41, 0x5f,
    /// Decrement refcount
        /* 57: movabs &refcount, %rbp           */ 0x48, 0xbd, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        /* 61: lock decq (%rbp)                 */ 0xf0, 0x48, 0xff, 0x4d, 0x00,
    /// Restore urgent registers (rsp, rbp, rflags)
        /* 66: popf                             */ 0x9d,
        /* 67: pop %rbp                         */ 0x5d,
        /* 68: pop %rsp                         */ 0x5c
    };
    constexpr size_t refcount_addr_1 = 0x05;
    constexpr size_t refcount_addr_2 = 0x59;
    constexpr size_t tp_addr = 0x2a;
    constexpr size_t handler_addr = 0x37;

    void safe_write8(void* where, uint64_t val) noexcept
    {
        asm volatile("lock xchg (%0), %1"::"r"(where),"r"(val) : "memory");
    }

    void set_refcount(uint8_t* code, uintptr_t refcount) noexcept
    {
        safe_write8(code + refcount_addr_1, refcount);
        safe_write8(code + refcount_addr_2, refcount);
    }

    void set_tracepoint(uint8_t* code, uintptr_t tp) noexcept
    {
        safe_write8(code + tp_addr, tp);
    }

    void set_handler(uint8_t* code, uintptr_t handler) noexcept
    {
        safe_write8(code + handler_addr, handler);
    }

    std::optional<int32_t> calc_jmp(uintptr_t from, uintptr_t to) noexcept
    {
        from += 5;
        auto diff = static_cast<int64_t>(to) - static_cast<int64_t>(from);
        if(diff < std::numeric_limits<int32_t>::min() || diff > std::numeric_limits<int32_t>::max())
            return std::nullopt;
        return static_cast<int32_t>(diff);
    }

    bool set_jmp(uint8_t* where, uintptr_t to)
    {
        auto odiff = calc_jmp(reinterpret_cast<uintptr_t>(where), to);
        if(!odiff)
            return false;
        auto diff = odiff.value();
        uint8_t bytes[8];
        memcpy(bytes, where, 8);
        bytes[0] = 0xe9;
        memcpy(bytes + 1, &diff, 4);
        safe_write8(where, *reinterpret_cast<uint64_t*>(bytes));
        return true;
    }
}

namespace dyntrace::fasttp
{
    void arch_tracepoint::do_insert(const process::process &proc)
    {
        
    }

    void arch_tracepoint::do_remove()
    {

    }

    void arch_tracepoint::handle(const tracer::regs &r)
    {
        try
        {
            _handler(_location, r);
        }
        catch (const std::exception& e)
        {
        }
        catch(...)
        {
        }
    }
}