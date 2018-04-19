#include "tracepoint.hpp"

#include "dyntrace/arch/arch.hpp"
#include "dyntrace/util/util.hpp"

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
    /* 14+ool: ldr pc, [pc, #offset] */

    struct point_tracepoint_stack
    {
        arch::regs regs;
        void* pc;
    };
}

extern "C" void point_tracepoint_handler(point_tracepoint_stack* st) noexcept
{
    auto data = reinterpret_cast<arch_tracepoint_data*>(st->pc);
}

extern "C" void __point_tracepoint_handler() noexcept;
extern size_t __point_tracepoint_handler_size;

arch_tracepoint::arch_tracepoint(void* location, dyntrace::fasttp::handler h, const dyntrace::fasttp::options& ops)
{

}

void arch_tracepoint::enable()
{

}

void arch_tracepoint::disable()
{

}

bool arch_tracepoint::enabled() const
{
    return false;
}

const void* arch_tracepoint::location() const
{
    return nullptr;
}