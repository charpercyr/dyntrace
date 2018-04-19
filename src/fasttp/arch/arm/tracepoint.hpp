#ifndef DYNTRACE_FASSTP_ARCH_ARM_TRACEPOINT_HPP_
#define DYNTRACE_FASSTP_ARCH_ARM_TRACEPOINT_HPP_

#include "context.hpp"

#include "dyntrace/fasttp/common.hpp"

#include "dyntrace/util/integer_range.hpp"

namespace dyntrace::fasttp
{
    class arch_tracepoint;

    struct arch_tracepoint_data
    {
        arch_tracepoint* tp;
        void* handler;
        void* return_address;
    };

    class arch_tracepoint
    {
    public:
        arch_tracepoint(void* location, handler h, const options& ops);

        void enable();
        void disable();
        bool enabled() const;

        const void* location() const;
    private:
    };
}

#endif