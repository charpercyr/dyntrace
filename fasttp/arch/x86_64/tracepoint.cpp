/**
 * Single tracepoint implementation for x86_64.
 */

#include "tracepoint.hpp"

#include "jmp.hpp"
#include "out_of_line.hpp"

#include <sys/mman.h>
#include <sys/user.h>

#include <fasttp/error.hpp>
#include <fasttp/fasttp.hpp>
#include <fasttp/common.hpp>
#include <fasttp/context.hpp>

using namespace dyntrace;
using namespace dyntrace::fasttp;

/**
 * 8-byte atomic write to location.
 */
extern "C" void do_safe_write8(volatile void* where, uint64_t val) noexcept;

namespace
{
    /**
     * Bytecode that saves the state and call the tracepoint. This code will be copied for every tracepoint.
     */
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

    /// Indices for the tracepoint's refcount variable address.
    constexpr size_t refcount_addr_1 = 0x05;
    /// Indices for the tracepoint's refcount variable address.
    constexpr size_t refcount_addr_2 = 0x59;
    /// Index for the insert location of the tracepoint.
    constexpr size_t tp_addr = 0x2a;
    /// Index for the address of the tracepoint handler.
    constexpr size_t handler_addr = 0x37;

    /// Opcode for a 5-byte jmp
    constexpr uint8_t jmp_op = 0xe9;
    /// Size for a 5-byte jmp.
    constexpr size_t jmp_size = 5;
    /// Opcode for a 1-byte trap
    constexpr uint8_t trap_op = 0xcc;

    void safe_write8(volatile void* where, uint64_t val) noexcept
    {
        do_safe_write8(where, val);
    }

    void set_refcount(code_ptr code, uintptr_t refcount) noexcept
    {
        safe_write8((code + refcount_addr_1).as_ptr(), refcount);
        safe_write8((code + refcount_addr_2).as_ptr(), refcount);
    }

    void set_tracepoint(code_ptr code, uintptr_t tp) noexcept
    {
        safe_write8((code + tp_addr).as_ptr(), tp);
    }

    void set_handler(code_ptr code, uintptr_t handler) noexcept
    {
        safe_write8((code + handler_addr).as_ptr(), handler);
    }

    /**
     * Calculates a jmp and atomically writes the instruction to where.
     */
    bool set_jmp(code_ptr where, code_ptr to) noexcept
    {
        auto odiff = calc_jmp(where.as_int(), to.as_int());
        if(!odiff)
            return false;
        auto diff = odiff.value();
        uint8_t bytes[8];
        *reinterpret_cast<uintptr_t*>(bytes) = *where.as<uintptr_t*>();
        bytes[0] = jmp_op;
        memcpy(bytes + 1, &diff, 4);
        safe_write8(where.as_ptr(), *reinterpret_cast<uint64_t*>(bytes));
        return true;
    }

    /**
     * Creates a condition object. The fixed bytes will be the first byte of every instruction but the first.
     */
    constraint make_constraint(uintptr_t start, const out_of_line &ool) noexcept
    {
        constraint res;
        for(const auto& insn : ool.instructions())
        {
            auto idx = insn->address() - start;
            if(idx != 0)
            {
                res[idx - 1] = trap_op;
            }
        }
        return res;
    };

    /**
     * Gets all the pages that contain [loc, loc + size)
     * @param loc
     * @param size
     * @return
     */
    std::pair<code_ptr, size_t> get_pages(code_ptr loc, size_t size) noexcept
    {
        // TODO better alloc
        size_t mmap_size = ((loc.as_int() & PAGE_MASK) - ((loc.as_int()  + size) & PAGE_MASK)) + PAGE_SIZE;
        loc = code_ptr{loc.as_int() & PAGE_MASK};
        return {loc, mmap_size};
    };
}
void arch_tracepoint::do_insert(const options& ops)
{
    if(!ops.x86.disable_jmp_safe)
    {
        // Check in the debug info that code doesn't jmp in the middle of the jmp.
        if(!_ctx->arch().basic_blocks())
        {
            throw fasttp_error{"No basic block information available"};
        }
        for (const auto &bb : _ctx->arch().basic_blocks().value())
        {
            if (bb.crosses(address_range{_location.as_int(), _location.as_int() + jmp_size}))
            {
                throw fasttp_error("Jump crosses basic block");
            }
        }
    }

    memcpy(&_old_code, _location.as_ptr(), 8);

    auto ool = out_of_line(_location);

    _handler_size = jmp_size + ool.size() + sizeof(handler_code);

    auto alloc = _ctx->arch().allocator();

    // Create handler in memory.
    constraint cond;
    if(!ops.x86.disable_thread_safe)
    {
        cond = make_constraint(_location.as_int(), ool);
    }
    _handler_location = alloc->alloc(_location + jmp_size, _handler_size, cond);

    memcpy(_handler_location.as_ptr(), handler_code, sizeof(handler_code));
    set_refcount(_handler_location, reinterpret_cast<uintptr_t>(&_refcount));
    set_tracepoint(_handler_location, reinterpret_cast<uintptr_t>(this));
    set_handler(_handler_location, reinterpret_cast<uintptr_t>(do_handle));
    _redirects = ool.write(_ctx->arch(), _handler_location + sizeof(handler_code), !ops.x86.disable_thread_safe, fasttp::handler{ops.x86.trap_handler});
    set_jmp(_handler_location + sizeof(handler_code) + ool.size(), _location + ool.size());

    enable();
}

void arch_tracepoint::do_remove()
{
    disable();
    // Wait for all tracepoints to be done executing and then unmap it.
    while(_refcount);
    auto alloc = _ctx->arch().allocator();
    alloc->free(_handler_location, _handler_size);
}

void arch_tracepoint::do_handle(const arch_tracepoint *self, const arch::regs &r) noexcept
{
    try
    {
        self->_user_handler(self->_location.as_ptr(), r);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Caught exception from handler: %s\n", e.what());
    }
    catch(...)
    {
        fprintf(stderr, "Caught unknown exception from handler\n");
    }
}

void arch_tracepoint::enable() noexcept
{
    if(!_enabled)
    {
        // Atomically place tracepoint.
        auto [pages_loc, pages_size] = get_pages(_location, 8);
        mprotect(pages_loc.as_ptr(), pages_size, PROT_WRITE | PROT_EXEC | PROT_READ);
        set_jmp(_location, _handler_location);
        mprotect(pages_loc.as_ptr(), pages_size, PROT_EXEC | PROT_READ);
        _enabled = true;
    }
}

void arch_tracepoint::disable() noexcept
{
    if(_enabled)
    {
        // Atomically remove tracepoint.
        auto [real_loc, mmap_size] = get_pages(_location, 8);
        mprotect(real_loc.as_ptr(), mmap_size, PROT_WRITE | PROT_EXEC | PROT_READ);
        safe_write8(_location.as_ptr(), _old_code);
        mprotect(real_loc.as_ptr(), mmap_size, PROT_EXEC | PROT_READ);
        _enabled = false;
    }
}