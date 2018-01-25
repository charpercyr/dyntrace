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

extern "C" void __tracepoint_handler() noexcept;
extern "C" void tracepoint_handler(arch::regs* regs) noexcept
{
    auto tp = reinterpret_cast<arch_tracepoint**>(regs->_res);
    (*tp)->call_handler(*regs);
    // The return address is the address of the tracepoint's data. We move it to the tracepoint exit code.
    regs->_res += sizeof(arch_tracepoint_data);
}

namespace
{
    constexpr uint8_t tracepoint_handler_enter_code[] = {
        /* 00: push %rsp              */ 0x54,
        /* 01: pushf                  */ 0x9c,
        /* 02: lock incq 0x16(%rip)   */ 0xf0, 0x48, 0xff, 0x05, 0x16, 0x00, 0x00, 0x00,
        /* 0a: callq *0x8(%rip)       */ 0xff, 0x15, 0x08, 0x00, 0x00, 0x00,
    };
        /* 10: arch_tracepoint*       */
        /* 18: tracepoint common code */
        /* 20: refcount (uint64_t)    */
    constexpr uint8_t tracepoint_handler_exit_code[] = {
        /* 28: lock decq -0x10(%rip)  */ 0xf0, 0x48, 0xff, 0x0d, 0xf0, 0xff, 0xff, 0xff,
        /* 30: popf                   */ 0x9d,
        /* 31: pop %rsp               */ 0x5c,
    };
        /* 32: ool                    */
        /* 32 + ool_size: jmp addr    */
    const arch_tracepoint_data init_tracepoint_data = {
        nullptr,
        reinterpret_cast<void*>(__tracepoint_handler),
        0
    };

    /// Opcode for a 5-byte jmp
    constexpr uint8_t jmp_op = 0xe9;
    /// Size for a 5-byte jmp.
    constexpr size_t jmp_size = 5;
    /// Opcode for a 1-byte trap
    constexpr uint8_t trap_op = 0xcc;

    size_t tracepoint_handler_size(size_t ool_size) noexcept
    {
        return
            sizeof(tracepoint_handler_enter_code) +
            sizeof(arch_tracepoint_data) +
            sizeof(tracepoint_handler_exit_code) +
            ool_size +
            jmp_size;
    }

    template<typename Int>
    std::enable_if_t<std::is_integral_v<Int>> atomic_store(volatile void *where, Int val) noexcept
    {
        __atomic_store(reinterpret_cast<volatile Int*>(where), &val, __ATOMIC_SEQ_CST);
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
        atomic_store(where.as_ptr(), *reinterpret_cast<uint64_t *>(bytes));
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

void arch_tracepoint::call_handler(const arch::regs &r) noexcept
{
    _user_handler(location(), r);
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

    _handler_size = tracepoint_handler_size(ool.size());

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
        atomic_store(_location.as_ptr(), _old_code);
        mprotect(real_loc.as_ptr(), mmap_size, PROT_EXEC | PROT_READ);
        _enabled = false;
    }
}

arch_tracepoint_data* arch_tracepoint::data()
{
    return (_handler_location + sizeof(tracepoint_handler_enter_code)).as<arch_tracepoint_data*>();
}