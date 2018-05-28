#ifndef DYNTRACE_FASTTP_ARCH_POWERPC_TRACEPOINT_HPP_
#define DYNTRACE_FASTTP_ARCH_POWERPC_TRACEPOINT_HPP_

#include "context.hpp"
#include "../../code_ptr.hpp"

#include "dyntrace/fasttp/common.hpp"

namespace dyntrace::fasttp
{
    class arch_tracepoint;

    struct arch_tracepoint_data
    {
        uintptr_t refcount{0};
        arch_tracepoint* tp;
        code_ptr _handler;
        size_t handler_size;
    };

    class arch_tracepoint
    {
    public:
        arch_tracepoint(void* location, handler h, const options& ops);

        void enable();
        void disable();
        bool enabled() const;

        void* location() const
        {
            return _location.as_ptr();
        }

        void call_handler(const arch::regs& regs) const;

    private:
        arch_tracepoint_data* _data;
        code_ptr _location;
        handler _h;
        uint32_t _old_code;
        bool _enabled;
    };
}

#endif