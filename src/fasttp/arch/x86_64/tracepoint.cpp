/**
 * Single tracepoint implementation for x86_64.
 */

#include "tracepoint.hpp"

#include "jmp.hpp"
#include "out_of_line.hpp"

#include <sys/mman.h>

#include "dyntrace/fasttp/error.hpp"
#include "dyntrace/fasttp/fasttp.hpp"
#include "dyntrace/fasttp/context.hpp"

#define PACKED __attribute__((packed))

using namespace dyntrace;
using namespace dyntrace::fasttp;

struct PACKED tracepoint_inline_data
{
    arch_tracepoint_code* tracepoint;
    void(*common_code)();
};

struct PACKED tracepoint_stack
{
    arch::regs regs;
    tracepoint_inline_data* inline_data;
};

struct PACKED tracepoint_return_inline_data
{
    arch_tracepoint_code* tracepoint;
    void(*common_enter_code)();
    void(*common_exit_code)();
};

struct PACKED tracepoint_return_enter_stack
{
    arch::regs regs;
    tracepoint_return_inline_data* inline_data;
    const void* return_address;
};

struct PACKED tracepoint_return_exit_stack
{
    arch::regs regs;
    union
    {
        tracepoint_return_inline_data* inline_data;
        const void *return_address;
    } data;
};

namespace
{
    // For normal tracepoint
    constexpr uint8_t tracepoint_handler_enter_code[] = {
        /* 00: callq *0x8(%rip)            */ 0xff, 0x15, 0x08, 0x00, 0x00, 0x00,
    };
        /* 06: arch_tracepoint_data        */
        /* 0e: __tracepoint_handler        */
        /* */
    constexpr uint8_t tracepoint_handler_exit_code[] = {
        /* 16: push %rbp                   */ 0x55,
        /* 17: pushf                       */ 0x9c,
        /* 18: mov -0x19(%rip), %rbp       */ 0x48, 0x8b, 0x2d, 0xe7, 0xff, 0xff, 0xff,
        /* 1f: lock decq (%rbp)            */ 0xf0, 0x48, 0xff, 0x4d, 0x00,
        /* 24: popf                        */ 0x9d,
        /* 25: pop %rbp                    */ 0x5d
    };
        /* 26: ool                         */
        /* 26+ool: jmp back                */

    // For enter/exit tracepoint
    constexpr uint8_t tracepoint_return_handler_code[] = {
        /* 00: callq *0xe(%rip)            */ 0xff, 0x15, 0x0e, 0x00, 0x00, 0x00, // Call for enter
        /* 06: callq *0x10(%rip)           */ 0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // Call for exit
    };
        /* 0c: arch_tracepoint_data        */
        /* 14: __tracepoint_handler        */
        /* 1c: __tracepoint_return_handler */
        /* 24: ool                         */
        /* 24+ool: jmp back                */

    /// Opcode for a 5-byte jmp
    constexpr uint8_t jmp_op = 0xe9;
    /// Size for a 5-byte jmp.
    constexpr size_t jmp_size = 5;
    /// Opcode for a 1-byte trap
    constexpr uint8_t trap_op = 0xcc;
    /// Size for a rip relative call
    constexpr size_t rip_call_size = 6;

    size_t tracepoint_handler_size(size_t ool_size) noexcept
    {
        return
            sizeof(tracepoint_handler_enter_code) +
            sizeof(tracepoint_inline_data) +
            ool_size +
            sizeof(tracepoint_handler_exit_code) +
            jmp_size;
    }

    size_t tracepoint_return_handler_size(size_t ool_size) noexcept
    {
        return
            sizeof(tracepoint_return_handler_code) +
            sizeof(tracepoint_return_inline_data) +
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

    template<typename F, typename...Args>
    void call_handler_nothrow(F&& f, Args&&...args) noexcept
    {
        try
        {
            f(std::forward<Args>(args)...);
        }
        catch (std::exception& e)
        {
            fprintf(stderr, "Caught exception during handler call: %s\n", e.what());
        }
        catch (...)
        {
            fprintf(stderr, "Caught unknown exception during handler call\n");
        }
    }

    template<typename T>
    T* advance(T* t, intptr_t off) noexcept
    {
        return reinterpret_cast<T*>(reinterpret_cast<uintptr_t>(t) + off);
    }
}

extern "C" void tracepoint_handler(tracepoint_stack* st) noexcept
{
    if(auto tp = st->inline_data->tracepoint->tracepoint.load())
    {
        tp->call_handler(st->regs);
    }
    // The return address is the address of the tracepoint's data. We move it to the tracepoint exit code.
    st->inline_data += 1;
}

thread_local const void* tracepoint_current_return_address;
extern "C" void tracepoint_return_enter_handler(tracepoint_return_enter_stack* st) noexcept
{
    tracepoint_current_return_address = st->return_address;
    // Inline data is pointing to the return call
    st->return_address = st->inline_data; // Replace return address with the handler's return address
    st->inline_data = advance(st->inline_data, rip_call_size);
    if(auto tp = st->inline_data->tracepoint->tracepoint.load())
    {
        tp->call_enter_handler(st->regs);
    }
    st->inline_data += 1;
}

extern "C" void tracepoint_return_exit_handler(tracepoint_return_exit_stack* st) noexcept
{
    if(auto tp = st->data.inline_data->tracepoint->tracepoint.load())
    {
        tp->call_exit_handler(st->regs);
        st->data.return_address = tracepoint_current_return_address;
    }
    else
    {
        fprintf(stderr, "Invalid return address\n");
        st->data.return_address = nullptr;
    }
}

void arch_tracepoint::call_handler(const arch::regs &r) noexcept
{
    call_handler_nothrow(std::get<point_handler>(_user_handler), location(), r);
}

void arch_tracepoint::call_enter_handler(const arch::regs &r) noexcept
{
    call_handler_nothrow(std::get<0>(std::get<entry_exit_handler>(_user_handler)), location(), r);
}

void arch_tracepoint::call_exit_handler(const arch::regs &r) noexcept
{
    call_handler_nothrow(std::get<1>(std::get<entry_exit_handler>(_user_handler)), location(), r);
}

arch_tracepoint::arch_tracepoint(void* location, handler h, const options& ops)
    : _user_handler{std::move(h)}, _trap_handler{ops.x86.trap_handler}, _location{location}
{
    bool is_point = std::holds_alternative<point_handler>(_user_handler);

    memcpy(&_old_code, _location.as_ptr(), 8);

    auto ool = out_of_line(_location);
    _ool_size = ool.size();

    auto handler_size = is_point ? tracepoint_handler_size(_ool_size) : tracepoint_return_handler_size(_ool_size);

    // Create handler in memory.
    constraint cond;
    if(!ops.x86.disable_thread_safe)
    {
        cond = make_constraint(_location.as_int(), ool);
    }

    code_ptr handler_location;
    {
        auto alloc = context::instance().arch().allocator();
        handler_location = alloc->alloc(_location + jmp_size, handler_size, cond);
    }
    if(!handler_location)
        throw fasttp_error{"Could not allocate tracepoint"};

    _code = new arch_tracepoint_code{0, handler_location, handler_size, this};

    buffer_writer writer{handler_location};
    if(is_point)
        writer.write(tracepoint_handler_enter_code);
    else
        writer.write(tracepoint_return_handler_code);
    writer.write(_code);
    if(is_point)
    {
        writer.write(__tracepoint_handler);
        writer.write(tracepoint_handler_exit_code);
    }
    else
    {
        writer.write(__tracepoint_return_enter_handler);
        writer.write(__tracepoint_return_exit_handler);
    }
    bool is_first = true;
    ool.write(writer, [code = _code, &is_first, this](code_ptr loc, code_ptr ool_loc)
    {
        if(is_first)
            is_first = false;
        else
        {
            _redirects.push_back(context::instance().arch().add_redirect(
                [code](const void* from, const arch::regs& regs)
                {
                    ++code->refcount;
                    if(auto tp = code->tracepoint.load(std::memory_order_relaxed))
                    {
                        if (tp->_trap_handler)
                            call_handler_nothrow(tp->_trap_handler, from, regs);
                    }
                },
                loc, ool_loc)
            );
        }
    });

    auto jmp = calc_jmp(writer.ptr().as_int(), (_location + _ool_size).as_int(), jmp_size);
    writer.write(jmp_op);
    writer.write(jmp.value());

    enable();
}

arch_tracepoint::~arch_tracepoint()
{
    disable();
    _code->tracepoint.store(nullptr, std::memory_order_seq_cst);
    context::instance().get_reclaimer().reclaim(
        [code = _code](uintptr_t rip) -> bool
        {
            return !(rip > code->handler.as_int() && rip < (code->handler.as_int() + code->handler_size)) && code->refcount.load() == 0;
        },
        [code = _code]() -> void
        {
            context::instance().arch().allocator()->free(code->handler, code->handler_size);
            delete code;
        }
    );
}

void arch_tracepoint::enable() noexcept
{
    if(!_enabled)
    {
        // Atomically place tracepoint.
        auto [pages_loc, pages_size] = get_pages(_location, 8);
        mprotect(pages_loc.as_ptr(), pages_size, PROT_WRITE | PROT_EXEC | PROT_READ);
        set_jmp(_location, _code->handler);
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