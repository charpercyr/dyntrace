
#include "tracepoint.hpp"

#include "dyntrace/arch/arch.hpp"
#include "dyntrace/util/util.hpp"

#include "dyntrace/fasttp/error.hpp"
#include "../../buffer_writer.hpp"
#include "../../context.hpp"

using namespace dyntrace::fasttp;

extern "C" void __point_tracepoint_handler();
extern "C" void __point_tracepoint_enter_code();
extern size_t __point_tracepoint_enter_code_size;
extern "C" void __point_tracepoint_exit_code();
extern size_t __point_tracepoint_exit_code_size;

namespace
{
    using namespace dyntrace;
    inline constexpr dyntrace::address_range alloc_range{1_M, 32_M};
    size_t point_tracepoint_size()
    {
        return
            __point_tracepoint_enter_code_size +
            sizeof(void*)*3 +
            4 +
            __point_tracepoint_exit_code_size;
    }

    uint32_t make_ba(code_ptr to)
    {
        //                                 op     target                        A L
        static constexpr uint32_t insn = 0b010010'0000'0000'0000'0000'0000'0000'1'0;
        dyntrace_assert(to.as_int() < (1 << 26) && !(to.as_int() & 0x3));
        return insn | (to.as_int() & ~0x3);
    }
}

extern "C" void point_tracepoint_handler(arch_tracepoint_data* data, dyntrace::arch::regs* regs)
{
    data->tp->call_handler(*regs);
}

arch_tracepoint::arch_tracepoint(void *location, dyntrace::fasttp::handler h, const dyntrace::fasttp::options &ops)
    : _location{location}, _h{std::move(h)}, _enabled{false}
{
    _old_code = *_location.as<uint32_t*>();
    _data = new arch_tracepoint_data;
    _data->tp = this;

    _data->handler_size = point_tracepoint_size();
    auto alloc = context::instance().arch().get_alloc();
    _data->_handler = code_ptr{alloc->alloc(_data->handler_size, alloc_range)};
    if(!_data->_handler)
    {
        delete _data;
        throw fasttp_error{"Could not allocate tracepoint"};
    }

    buffer_writer writer{_data->_handler};
    writer.write_bytes(
        reinterpret_cast<void*>(__point_tracepoint_enter_code),
        __point_tracepoint_enter_code_size
    );
    writer.write(_data);
    writer.write(__point_tracepoint_handler);
    writer.write(_location.as_ptr());
    writer.write(*_location.as<uint32_t*>());
    writer.write_bytes(
        reinterpret_cast<void*>(__point_tracepoint_exit_code),
        __point_tracepoint_exit_code_size
    );

    enable();
}

void arch_tracepoint::enable()
{
    if(!_enabled)
    {
        mprotect((_location & page_mask).as_ptr(), page_size, PROT_EXEC | PROT_READ | PROT_WRITE);
        __atomic_store_4(_location.as<uint32_t*>(), make_ba(_data->_handler), __ATOMIC_SEQ_CST);
        mprotect((_location & page_mask).as_ptr(), page_size, PROT_EXEC | PROT_READ);
        _enabled = true;
    }
}

void arch_tracepoint::disable()
{
    if(_enabled)
    {
        mprotect((_location & page_mask).as_ptr(), page_size, PROT_EXEC | PROT_READ | PROT_WRITE);
        __atomic_store_4(_location.as<uint32_t*>(), _old_code, __ATOMIC_SEQ_CST);
        mprotect((_location & page_mask).as_ptr(), page_size, PROT_EXEC | PROT_READ);
        _enabled = false;
    }
}

bool arch_tracepoint::enabled() const
{
    return _enabled;
}

void arch_tracepoint::call_handler(const dyntrace::arch::regs &regs) const
{
    try
    {
        std::get<point_handler>(_h)(_location.as_ptr(), regs);
    }
    catch(...)
    {

    }
}