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

struct __attribute__((packed)) tracepoint_inline_data
{
    arch_tracepoint* tracepoint;
    void(*common_code)();
};

struct __attribute__((packed)) tracepoint_stack
{
    arch::regs regs;
    tracepoint_inline_data* inline_data;
};

extern "C" void __attribute__((used)) tracepoint_handler(tracepoint_stack* st) noexcept
{
    st->inline_data->tracepoint->call_handler(st->regs);
    // The return address is the address of the tracepoint's data. We move it to the tracepoint exit code.
    st->inline_data += 1;
}

namespace
{
    constexpr uint8_t tracepoint_handler_enter_code[] = {
        /* 00: callq *0x8(%rip)                */ 0xff, 0x15, 0x08, 0x00, 0x00, 0x00,
    };
        /* 06: arch_tracepoint_data            */
        /* 0e: __tracepoint_handler            */
        /* 16: ool                             */
    constexpr uint8_t tracepoint_handler_exit_code[] = {
        /* 16+ool: push %rbp                   */ 0x55,
        /* 17+ool: pushf                       */ 0x9c,
        /* 18+ool: mov (-19 - ool)(%rip), %rbp */ 0x48, 0x8b, 0x2d, 0xef, 0xbe, 0xad, 0xde,
        /* 1f+ool: lock decq 0x10(%rbp)        */ 0xf0, 0x48, 0xff, 0x4d, 0x10,
        /* 24+ool: popf                        */ 0x9d,
        /* 25+ool: pop %rbp                    */ 0x5d
    };
        /* 26+ool: jmp back                    */

    /// Opcode for a 5-byte jmp
    constexpr uint8_t jmp_op = 0xe9;
    /// Size for a 5-byte jmp.
    constexpr size_t jmp_size = 5;
    /// Opcode for a 1-byte trap
    constexpr uint8_t trap_op = 0xcc;

    constexpr size_t tracepoint_handler_exit_code_offset_idx = 5;
    constexpr int32_t tracepoint_handler_exit_code_offset_base = -0x19;

    size_t tracepoint_handler_size(size_t ool_size) noexcept
    {
        return
            sizeof(tracepoint_handler_enter_code) +
            sizeof(tracepoint_inline_data) +
            ool_size +
            sizeof(tracepoint_handler_exit_code) +
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
        auto odiff = calc_jmp(where.as_int(), to.as_int(), jmp_size);
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
    try
    {
        _user_handler(location(), r);
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

arch_tracepoint::arch_tracepoint(void* location, handler h, const options& ops)
    : _location{location}, _user_handler{std::move(h)}, _trap_handler{ops.x86.trap_handler}
{
    memcpy(&_old_code, _location.as_ptr(), 8);

    auto ool = out_of_line(_location);
    auto ool_size = ool.size();

    _handler_size = tracepoint_handler_size(ool_size);

    // Create handler in memory.
    constraint cond;
    if(!ops.x86.disable_thread_safe)
    {
        cond = make_constraint(_location.as_int(), ool);
    }
    _handler_location = context::instance().arch().allocator()->alloc(_location + jmp_size, _handler_size, cond);
    if(!_handler_location)
        throw fasttp_error{"Could not allocate tracepoint"};

    buffer_writer writer{_handler_location};

    writer.write(tracepoint_handler_enter_code);
    writer.write(this);
    writer.write(__tracepoint_handler);
    bool is_first = true;
    ool.write(writer, [&is_first, this](code_ptr loc, code_ptr ool_loc)
    {
        if(is_first)
            is_first = false;
        else
        {
            _redirects.push_back(context::instance().arch().add_redirect(
                [this](const void* from, const arch::regs& regs)
                {
                    try
                    {
                        ++_refcount;
                        if(_trap_handler)
                            _trap_handler(from, regs);
                    }
                    catch (const std::exception& e)
                    {
                        fprintf(stderr, "Caught exception from trap_handler: %s\n", e.what());
                    }
                    catch(...)
                    {
                        fprintf(stderr, "Caught unknown exception from trap_handler\n");
                    }
                },
                loc, ool_loc)
            );
        }
    });
    auto cur = writer.ptr();
    writer.write(tracepoint_handler_exit_code);
    *(cur + tracepoint_handler_exit_code_offset_idx).as<int32_t*>() = tracepoint_handler_exit_code_offset_base - ool_size;

    auto jmp = calc_jmp(writer.ptr().as_int(), (_location + ool_size).as_int(), jmp_size);
    writer.write(jmp_op);
    writer.write(jmp.value());
}

arch_tracepoint::~arch_tracepoint()
{
    disable();
    auto alloc = context::instance().arch().allocator();
    alloc->free(_handler_location, _handler_size);
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

std::shared_ptr<arch_tracepoint> arch_tracepoint::make(void* location, handler h, const options& ops, deleter del)
{
    auto res = std::shared_ptr<arch_tracepoint>{new arch_tracepoint{location, std::move(h), ops}, std::move(del)};
    res->enable();
    return res;
}