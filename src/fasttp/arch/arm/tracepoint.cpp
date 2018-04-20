#include <dyntrace/fasttp/error.hpp>
#include "tracepoint.hpp"

#include "dyntrace/arch/arch.hpp"
#include "dyntrace/util/util.hpp"

#include "../../buffer_writer.hpp"
#include "../../context.hpp"
#include "context.hpp"

using namespace dyntrace;
using namespace dyntrace::fasttp;

namespace
{
    uint32_t point_tracepoint_entry_code[] = {
        /* 00: push {r0-r12, lr, pc} */ 0xe92ddfff,
        /* 04: ldr pc, [pc]          */ 0xe59ff000,
    };
    /*     08: tracepoint data       */
    /*     0c: tracepoint handler    */
    /*     10: return address        */
    /*     14: ool                   */
    uint32_t point_tracepoint_exit_code[] = {
    /*     18: ldr pc, [pc, #offset] */ 0xe51ff010
    };

    constexpr size_t tracepoint_code_size() noexcept
    {
        return sizeof(point_tracepoint_entry_code) + 16 + sizeof(point_tracepoint_exit_code);
    }

    struct point_tracepoint_stack
    {
        arch::regs regs;
        void* pc;
    };

    template<typename T, typename...Args>
    T* construct(void* addr, Args&&...args)
    {
        if(!addr)
            return nullptr;
        return new(addr) T{std::forward<Args>(args)...};
    }

    arch_tracepoint_pad* new_pad(code_ptr loc, void* handler)
    {
        constexpr static uint32_t insn = /* ldr pc, [pc, #-4] */ 0xe51ff004;
        auto alloc = context::instance().arch().pad_alloc();
        auto addr = alloc->alloc(sizeof(arch_tracepoint_pad), address_range_around(loc.as_int(), 32_M - page_size - 8));
        if(!addr)
            return nullptr;
        return construct<arch_tracepoint_pad>(addr, insn, handler);
    }

    void delete_pad(arch_tracepoint_pad* pad)
    {
        auto alloc = context::instance().arch().pad_alloc();
        alloc->free(pad, sizeof(arch_tracepoint_pad));
    }
}

extern "C" void point_tracepoint_handler(point_tracepoint_stack* st) noexcept
{
    auto data = *reinterpret_cast<arch_tracepoint_data**>(st->pc);
    data->tp->call_handler(st->regs);
    st->pc = offset_cast<void>(st->pc, 12);
}

extern "C" void __point_tracepoint_handler() noexcept;
extern size_t __point_tracepoint_handler_size;

arch_tracepoint::arch_tracepoint(void* location, handler h, const dyntrace::fasttp::options& ops)
    : _h{std::move(h)}
{
    if(std::holds_alternative<entry_exit_handler>(_h))
        throw fasttp_error{"Entry-Exit not supported"};

    _location = code_ptr{location};

    memcpy(&_old_code, location, 4);
    _data = new arch_tracepoint_data;
    if(!_data)
        throw fasttp_error{"Could not allocate tracepoint data"};
    _data->tp = this;

    auto code_alloc = context::instance().arch().code_alloc();
    _data->handler_size = tracepoint_code_size();
    _data->handler = code_ptr{code_alloc->alloc(_data->handler_size)};
    if(!_data->handler)
    {
        delete _data;
        throw fasttp_error{"Could not allocate tracepoint code"};
    }

    _data->pad = new_pad(_location, _data->handler.as_ptr());
    if(!_data->pad)
    {
        code_alloc->free(_data->handler.as_ptr(), _data->handler_size);
        delete _data;
        throw fasttp_error{"Could not allocation tracepoint jump pad"};
    }

    buffer_writer writer{_data->handler};
    writer.write(point_tracepoint_entry_code);
    writer.write(_data);
    writer.write(__point_tracepoint_handler);
    writer.write((_location + 4).as_ptr());
    writer.write(_old_code);
    writer.write(point_tracepoint_exit_code);

    enable();
}

arch_tracepoint::~arch_tracepoint()
{
    disable();
    delete_pad(_data->pad);
    auto code_alloc = context::instance().arch().code_alloc();
    code_alloc->free(_data->handler.as_ptr(), _data->handler_size);
    delete _data;
}

void arch_tracepoint::enable()
{
    /*                                   cond --- L offset */
    static constexpr uint32_t b_base = 0b1110'101'0'0000'0000'0000'0000'0000'0000;
    static constexpr uint32_t o_mask = 0b0000'000'0'1111'1111'1111'1111'1111'1111;
    int32_t offset = reinterpret_cast<uintptr_t>(_data->pad) - (_location.as_int() + 8);
    dyntrace_assert(abs(offset) < 32_M);
    offset >>= 2;
    uint32_t insn = b_base | (offset & o_mask);
    mprotect((_location & page_mask).as_ptr(), page_size, PROT_WRITE | PROT_READ | PROT_EXEC);
    __atomic_store_4(_location.as_ptr(), insn, __ATOMIC_SEQ_CST);
    mprotect((_location & page_mask).as_ptr(), page_size, PROT_READ | PROT_EXEC);
}

void arch_tracepoint::disable()
{
    mprotect((_location & page_mask).as_ptr(), page_size, PROT_WRITE | PROT_READ | PROT_EXEC);
    __atomic_store_4(_location.as_ptr(), _old_code, __ATOMIC_SEQ_CST);
    mprotect((_location & page_mask).as_ptr(), page_size, PROT_READ | PROT_EXEC);
}

bool arch_tracepoint::enabled() const
{
    return false;
}

const void* arch_tracepoint::location() const
{
    return nullptr;
}

void arch_tracepoint::call_handler(const dyntrace::arch::regs& r) noexcept
{
    try
    {
        std::get<point_handler>(_h)(_location.as_ptr(), r);
    }
    catch(...)
    {
        fprintf(stderr, "Catched exception in handler\n");
    }
}