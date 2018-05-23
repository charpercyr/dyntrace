#ifndef DYNTRACE_FASTTP_ARCH_POWERPC_TRACEPOINT_HPP_
#define DYNTRACE_FASTTP_ARCH_POWERPC_TRACEPOINT_HPP_

#include "context.hpp"

#include "dyntrace/fasttp/common.hpp"

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

        void* location() const
        {
            return nullptr;
        }
    };
}

#endif