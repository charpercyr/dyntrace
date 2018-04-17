#ifndef DYNTRACE_FASSTP_ARCH_ARM_TRACEPOINT_HPP_
#define DYNTRACE_FASSTP_ARCH_ARM_TRACEPOINT_HPP_

#include "context.hpp"

#include "dyntrace/fasttp/common.hpp"

#include "dyntrace/util/integer_range.hpp"

namespace dyntrace::fasttp
{
    class arch_tracepoint
    {
    public:
        arch_tracepoint(void* location, handler h, const options& ops)
        {

        }

        void enable()
        {

        }

        void disable()
        {

        }

        bool enabled() const
        {
            return false;
        }

        const void* location() const
        {
            return nullptr;
        }
    };
}

#endif