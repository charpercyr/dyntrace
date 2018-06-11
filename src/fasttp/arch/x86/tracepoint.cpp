/**
 * Single tracepoint implementation for x86_64.
 */

#include "tracepoint.hpp"

#include "jmp.hpp"
#include "out_of_line.hpp"

#include <random>
#include <sys/mman.h>

#include "dyntrace/fasttp/error.hpp"
#include "dyntrace/fasttp/fasttp.hpp"
#include "../../context.hpp"

#define PACKED __attribute__((packed))

using namespace dyntrace;
using namespace dyntrace::fasttp;

struct PACKED tracepoint_inline_data
{
    arch_tracepoint_code* tracepoint;
    void(*common_code)();
};

struct PACKED tracepoint_return_inline_data
{
    arch_tracepoint_code* tracepoint;
    void(*common_enter_code)();
    void(*common_exit_code)();
};

#ifdef __i386__
using tracepoint_stack = arch::regs;
struct PACKED tracepoint_return_enter_stack
{
    arch::regs regs;
    const void* return_address;
};
using tracepoint_return_exit_stack = tracepoint_return_enter_stack;
#else
struct PACKED tracepoint_stack
{
    arch::regs regs;
    tracepoint_inline_data* inline_data;
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

#endif

namespace
{
#ifdef __i386__
    // For normal tracepoint
    constexpr uint8_t tracepoint_handler_enter_code[] = {
        /* 00: push %ebp                   */ 0x55,
        /* 01: call 0                      */ 0xe8, 0x00, 0x00, 0x00, 0x00,
        /* 06: pop %ebp                    */ 0x5d,
        /* 07: call *0x8(%ebp)             */ 0xff, 0x55, 0x08
    };
        /* 0a: arch_tracepoint_data        */
        /* 0e: __tracepoint_handler        */
    constexpr uint8_t tracepoint_handler_exit_code[] = {
        /* 12: pushf                       */ 0x9c,
        /* 13: call 0                      */ 0xe8, 0x00, 0x00, 0x00, 0x00,
        /* 18: pop %ebp                    */ 0x5d,
        /* 19: mov -0xe(%ebp), %ebp        */ 0x8b, 0x6d, 0xf2,
        /* 1c: lock decl (%ebp)            */ 0xf0, 0xff, 0x4d, 0x00,
        /* 20: popf                        */ 0x9d,
        /* 21: pop %ebp                    */ 0x5d,
    };
        /* 21: ool                         */
        /* 21+ool: jmp back                */

    constexpr uint8_t tracepoint_return_handler_code[] = {
        /* 00: push %ebp                   */ 0x55,
        /* 01: call 0                      */ 0xe8, 0x00, 0x00, 0x00, 0x00,
        /* 06: pop %ebp                    */ 0x5d,
        /* 07: call 0x14(%ebp)             */ 0xff, 0x55, 0x14,
        /* 0a: push $0                     */ 0x6a, 0x00,
        /* 0c: push %ebp                   */ 0x55,
        /* 0d: call 0                      */ 0xe8, 0x00, 0x00, 0x00, 0x00,
        /* 12: pop %ebp                    */ 0x5d,
        /* 13: call 0x0c(%ebp)             */ 0xff, 0x55, 0x0c
    };
        /* 16: arch_tracepoint_data        */
        /* 1a: __tracepoint_handler        */
        /* 1e: __tracepoint_return_handler */
    constexpr uint8_t tracepoint_return_handler_code_exit[] = {
        /* 22: pop %ebp                    */ 0x5d,
    };
        /* 23: ool                         */
        /* 23+ool: jmp_back                */

    /// Size for a rip relative call
    constexpr size_t tracepoint_enter_data_disp = 12;
#else // __i386__
    // For normal tracepoint
    constexpr uint8_t tracepoint_handler_enter_code[] = {
        // Skip the red zone since it could potentially be used by leaf functions
        /* 00: lea -0x80(%rsp), %rsp       */ 0x48, 0x8d, 0x64, 0x24, 0x80,
        /* 05: call *0x8(%rip)             */ 0xff, 0x15, 0x08, 0x00, 0x00, 0x00,
    };
        /* 0b: arch_tracepoint_data        */
        /* 13: __tracepoint_handler        */
    constexpr uint8_t tracepoint_handler_exit_code[] = {
        /* 1a: push %rbp                   */ 0x55,
        /* 1b: pushf                       */ 0x9c,
        /* 1c: mov -0x19(%rip), %rbp       */ 0x48, 0x8b, 0x2d, 0xe7, 0xff, 0xff, 0xff,
        /* 24: lock decq (%rbp)            */ 0xf0, 0x48, 0xff, 0x4d, 0x00,
        /* 29: popf                        */ 0x9d,
        /* 2a: pop %rbp                    */ 0x5d,
        /* 2b: lea 0x80(%rsp), %rsp        */ 0x48, 0x8d, 0xa4, 0x24, 0x80, 0x00, 0x00, 0x00,
    };
        /* 33: ool                         */
        /* 33+ool: jmp back                */

    // For enter/exit tracepoint
    constexpr uint8_t tracepoint_return_handler_code[] = {
        /* 00: call *0xe(%rip)             */ 0xff, 0x15, 0x0e, 0x00, 0x00, 0x00, // Call for enter
        /* 06: call *0x10(%rip)            */ 0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // Call for exit
    };
        /* 0c: arch_tracepoint_data        */
        /* 14: __tracepoint_handler        */
        /* 1c: __tracepoint_return_handler */
    constexpr uint8_t tracepoint_return_handler_code_exit[0] = {};
        /* 24: ool                         */
        /* 24+ool: jmp back                */

    /// Size for a rip relative call
    constexpr size_t tracepoint_enter_data_disp = 6;
#endif // __i386__

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
            sizeof(tracepoint_inline_data) +
            sizeof(tracepoint_handler_exit_code) +
            ool_size +
            jmp_size;
    }

    size_t tracepoint_return_handler_size(size_t ool_size) noexcept
    {
        return
            sizeof(tracepoint_return_handler_code) +
            sizeof(tracepoint_return_inline_data) +
            sizeof(tracepoint_return_handler_code_exit) +
            ool_size +
            jmp_size;
    }

    template<typename T>
    T* advance(T* t, intptr_t off) noexcept
    {
        return reinterpret_cast<T*>(reinterpret_cast<uintptr_t>(t) + off);
    }

#ifdef __i386__

    void atomic_store_jmp(volatile void* where, uint64_t _val) noexcept
    {
        auto val = reinterpret_cast<uint8_t*>(&_val);
        __atomic_store(reinterpret_cast<volatile uint8_t*>(where), &trap_op, __ATOMIC_SEQ_CST);
        where = advance(where, 1);
        __atomic_store(reinterpret_cast<volatile int32_t*>(where), reinterpret_cast<int32_t*>(val + 1), __ATOMIC_SEQ_CST);
        where = advance(where, -1);
        __atomic_store(reinterpret_cast<volatile uint8_t*>(where), val, __ATOMIC_SEQ_CST);
    }
#else
    void atomic_store_jmp(volatile void *where, uint64_t val) noexcept
    {
        __atomic_store(reinterpret_cast<volatile uint64_t*>(where), &val, __ATOMIC_SEQ_CST);
    }
#endif

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
        *reinterpret_cast<uint64_t*>(bytes) = *where.as<uint64_t*>();
        bytes[0] = jmp_op;
        memcpy(bytes + 1, &diff, 4);
        atomic_store_jmp(where.as_ptr(), *reinterpret_cast<uint64_t*>(bytes));
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
        size_t mmap_size = (((loc.as_int() + size) & PAGE_MASK) - (loc.as_int() & PAGE_MASK)) + PAGE_SIZE;
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

}

extern "C" void tracepoint_handler(tracepoint_stack* st) noexcept
{
#ifdef __i386__
    auto inline_data = reinterpret_cast<tracepoint_inline_data*>(st->_res);
    const auto& regs = *st;
    st->sp += 8; // sp is 8 bytes too far (it is not pushed first)
#else
    auto inline_data = st->inline_data;
    const auto& regs = st->regs;
    st->regs.sp += 128; // sp is 128 bytes too far (red zone)
#endif
    if(auto tp = inline_data->tracepoint->tracepoint.load())
    {
        tp->call_handler(regs);
    }
#ifdef __i386__
    st->sp -= 8;
    // The return address is the address of the tracepoint's data. We move it to the tracepoint exit code.
    st->_res += sizeof(tracepoint_inline_data);
#else
    st->regs.sp -= 128;
    // The return address is the address of the tracepoint's data. We move it to the tracepoint exit code.
    st->inline_data += 1;
#endif
}

thread_local const void* tracepoint_current_return_address;
extern "C" void tracepoint_return_enter_handler(tracepoint_return_enter_stack* st) noexcept
{
    tracepoint_current_return_address = st->return_address;
#ifdef __i386__
    st->return_address = reinterpret_cast<const void*>(st->regs._res);
    auto inline_data = reinterpret_cast<tracepoint_return_inline_data*>(st->regs._res + tracepoint_enter_data_disp);
    st->regs.sp += 8;
#else
    // Inline data is pointing to the return call
    st->return_address = st->inline_data;
    st->inline_data = advance(st->inline_data, tracepoint_enter_data_disp);
    auto inline_data = st->inline_data;
#endif
    if(auto tp = inline_data->tracepoint->tracepoint.load())
    {
        tp->call_enter_handler(st->regs);
    }
#ifdef __i386__
    st->regs.sp -= 8;
    st->regs._res += tracepoint_enter_data_disp + sizeof(tracepoint_return_inline_data);
#else
    st->inline_data += 1;
#endif
}

extern "C" void tracepoint_return_exit_handler(tracepoint_return_exit_stack* st) noexcept
{
#ifdef __i386__
    auto inline_data = reinterpret_cast<tracepoint_inline_data*>(st->regs._res);
#else
    auto inline_data = st->data.inline_data;
#endif
    if(auto tp = inline_data->tracepoint->tracepoint.load())
    {
        tp->call_exit_handler(st->regs);
    }
    else
    {
        fprintf(stderr, "Invalid return address, SHOULD NOT HAPPEN\n");
        fflush(stderr);
        std::terminate();
    }
#ifdef __i386__
    st->return_address = tracepoint_current_return_address;
#else
    st->data.return_address = tracepoint_current_return_address;
#endif
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
    handler_size = next_pow2(handler_size);

    code_ptr handler_location;
    {
        if(auto _data = reclaimer::instance().cancel(_location.as_int()))
        {
            auto code = std::any_cast<arch_tracepoint_code*>(_data.value().data);
            if (code->handler_size >= handler_size)
            {
                handler_location = code->handler;
                _code = code;
                _code->tracepoint = this;
            }
            else
            {
                reclaimer::instance().reclaim(std::mt19937_64(clock())(), std::move(_data.value()));
            }
        }
        if(!handler_location)
        {
            // Create handler in memory.
            constraint cond;
            if(!ops.x86.disable_thread_safe)
            {
                cond = make_constraint(_location.as_int(), ool);
            }
            auto alloc = context::instance().arch().allocator();
            handler_location = alloc->alloc(_location + jmp_size, handler_size, cond);
            _code = new arch_tracepoint_code{0, handler_location, handler_size, this};
        }
    }
    if(!handler_location)
        throw fasttp_error{"Could not allocate tracepoint"};

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
        writer.write(tracepoint_return_handler_code_exit);
    }
    bool is_first = true;
    ool.write(writer, [code = _code, &is_first, this](code_ptr loc, code_ptr ool_loc)
    {
#ifdef __x86_64__
        if(is_first)
            is_first = false;
        else
        {
#endif
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
#ifdef __x86_64__
        }
#endif
    });

    auto jmp = calc_jmp(writer.ptr().as_int(), (_location + ool.ool_size()).as_int(), jmp_size);
    writer.write(jmp_op);
    writer.write(jmp.value());

    enable();
}

arch_tracepoint::~arch_tracepoint()
{
    disable();
    _code->tracepoint.store(nullptr, std::memory_order_seq_cst);
    reclaimer::instance().reclaim(
        _location.as_int(),
        reclaimer::reclaim_request{
            [code = _code](uintptr_t rip) -> bool
            {
                return !(rip > code->handler.as_int() && rip < (code->handler.as_int() + code->handler_size)) &&
                       code->refcount.load() == 0;
            },
            [code = _code]() -> void
            {
                context::instance().arch().allocator()->free(code->handler, code->handler_size);
                delete code;
            },
            _code
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
        atomic_store_jmp(_location.as_ptr(), _old_code);
        mprotect(real_loc.as_ptr(), mmap_size, PROT_EXEC | PROT_READ);
        _enabled = false;
    }
}