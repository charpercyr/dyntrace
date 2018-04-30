#include <dyntrace/fasttp/error.hpp>
#include "tracepoint.hpp"

#include "dyntrace/arch/arch.hpp"
#include "dyntrace/util/util.hpp"

#include "../../buffer_writer.hpp"
#include "../../context.hpp"
#include "context.hpp"
#include "out_of_line.hpp"

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

    uint32_t ee_tracepoint_entry_code[] = {
        /* 00: push {r0-r12, lr, pc} */ 0xe92ddfff,
        /* 04: ldr pc, [pc, #8]      */ 0xe59ff008,
    };
    uint32_t ee_tracepoint_return_code[] = {
        /* 08: push {r0-r12, lr, pc} */ 0xe92ddfff,
        /* 0c: ldr pc, [pc, #4]      */ 0xe59ff004,
    };
    /*     10: tracepoint data       */
    /*     14: tracepoint entry h    */
    /*     18: tracepoint return h   */
    /*     1c: return address        */
    /*     20: ool                   */

    size_t point_tracepoint_code_size(size_t ool) noexcept
    {
        return sizeof(point_tracepoint_entry_code) + 8 + ool;
    }
    size_t ee_tracepoint_code_size(size_t ool) noexcept
    {
        return sizeof(ee_tracepoint_entry_code) + sizeof(ee_tracepoint_return_code) + 16 + ool;
    }

    struct tracepoint_stack
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

    template<typename Func, typename...Args>
    decltype(auto) call_nothrow(Func&& func, Args&&...args) noexcept
    {
        try
        {
            return std::forward<Func>(func)(std::forward<Args>(args)...);
        }
        catch(const std::exception& e)
        {
            fprintf(stderr, "Catched exception in handler: %s\n", e.what());
        }
        catch(...)
        {
            fprintf(stderr, "Catched unknown exception in handler\n");
        }
    }
}

extern "C" void point_tracepoint_handler(tracepoint_stack* st) noexcept
{
    auto data = *reinterpret_cast<arch_tracepoint_data**>(st->pc);
    data->tp.load(std::memory_order_relaxed)->call_handler(st->regs);
    st->pc = offset_cast<void>(st->pc, 12);
}
extern "C" void __point_tracepoint_handler() noexcept;
extern size_t __point_tracepoint_handler_size;

static thread_local uintptr_t current_tracepoint_return_address;
extern "C" void ee_tracepoint_entry_handler(tracepoint_stack* st) noexcept
{
    auto data = *offset_cast<arch_tracepoint_data*>(st->pc, 8);
    data->tp.load(std::memory_order_relaxed)->call_entry_handler(st->regs);
    current_tracepoint_return_address = st->regs.lr;
    st->regs.lr = reinterpret_cast<uintptr_t>(st->pc);
    st->pc = offset_cast<void>(st->pc, 24);
}
extern "C" void __ee_tracepoint_entry_handler() noexcept;
extern size_t __ee_tracepoint_entry_handler_size;

extern "C" void ee_tracepoint_return_handler(tracepoint_stack* st) noexcept
{
    auto data = *reinterpret_cast<arch_tracepoint_data**>(st->pc);
    data->tp.load(std::memory_order_relaxed)->call_exit_handler(st->regs);
    st->pc = reinterpret_cast<void*>(current_tracepoint_return_address);
}
extern "C" void __ee_tracepoint_return_handler() noexcept;
extern size_t __ee_tracepoint_return_handler_size;


arch_tracepoint::arch_tracepoint(void* location, handler h, const dyntrace::fasttp::options& ops)
    : _h{std::move(h)}
{
    bool is_ee = std::holds_alternative<entry_exit_handler>(_h);

    _location = code_ptr{location};

    memcpy(&_old_code, location, 4);
    _data = new arch_tracepoint_data;
    if(!_data)
        throw fasttp_error{"Could not allocate tracepoint data"};
    _data->tp = this;

    out_of_line ool{_location};

    auto code_alloc = context::instance().arch().code_alloc();
    if(is_ee)
        _data->handler_size = ee_tracepoint_code_size(ool.size());
    else
        _data->handler_size = point_tracepoint_code_size(ool.size());
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
    if(is_ee)
    {
        writer.write(ee_tracepoint_entry_code);
        writer.write(ee_tracepoint_return_code);
    }
    else
        writer.write(point_tracepoint_entry_code);
    writer.write(_data);
    if(is_ee)
    {
        writer.write(__ee_tracepoint_entry_handler);
        writer.write(__ee_tracepoint_return_handler);
    }
    else
        writer.write(__point_tracepoint_handler);
    writer.write((_location + 4).as_ptr());
    ool.write(writer);

    enable();
}

arch_tracepoint::~arch_tracepoint()
{
    disable();
    _data->tp = nullptr;
    reclaimer::instance().reclaim(
        _location.as_int(),
        reclaimer::reclaim_request{
            [data = _data](uintptr_t pc) -> bool
            {
                return !(
                    pc > data->handler.as_int() &&
                    pc < (data->handler.as_int() + data->handler_size) &&
                    pc > reinterpret_cast<uintptr_t>(data->pad) &&
                    pc < reinterpret_cast<uintptr_t>(data->pad + 1)
                );
            },
            [data = _data]() -> void
            {
                delete_pad(data->pad);
                auto code_alloc = context::instance().arch().code_alloc();
                code_alloc->free(data->handler.as_ptr(), data->handler_size);
                delete data;
            },
            _data
        }
    );
}

void arch_tracepoint::enable()
{
    /*                                   cond --- L offset */
    static constexpr uint32_t b_base = 0b1110'101'0'0000'0000'0000'0000'0000'0000;
    static constexpr uint32_t o_mask = 0b0000'000'0'1111'1111'1111'1111'1111'1111;
    int32_t offset = reinterpret_cast<uintptr_t>(_data->pad) - (_location.as_int() + 8);
    dyntrace_assert(uint32_t(abs(offset)) < 32_M);
    offset >>= 2;
    uint32_t insn = b_base | (offset & o_mask);
    mprotect((_location & page_mask).as_ptr(), page_size, PROT_WRITE | PROT_READ | PROT_EXEC);
    __atomic_store(_location.as<uint32_t*>(), &insn, __ATOMIC_SEQ_CST);
    mprotect((_location & page_mask).as_ptr(), page_size, PROT_READ | PROT_EXEC);
}

void arch_tracepoint::disable()
{
    mprotect((_location & page_mask).as_ptr(), page_size, PROT_WRITE | PROT_READ | PROT_EXEC);
    __atomic_store(_location.as<uint32_t*>(), &_old_code, __ATOMIC_SEQ_CST);
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
    call_nothrow(std::get<point_handler>(_h), _location.as_ptr(), r);
}

void arch_tracepoint::call_entry_handler(const dyntrace::arch::regs& r) noexcept
{
    call_nothrow(std::get<0>(std::get<entry_exit_handler>(_h)), _location.as_ptr(), r);
}

void arch_tracepoint::call_exit_handler(const dyntrace::arch::regs& r) noexcept
{
    call_nothrow(std::get<1>(std::get<entry_exit_handler>(_h)), _location.as_ptr(), r);
}