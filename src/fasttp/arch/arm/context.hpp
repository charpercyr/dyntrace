#ifndef DYNTRACE_FASSTP_ARCH_ARM_CONTEXT_HPP_
#define DYNTRACE_FASSTP_ARCH_ARM_CONTEXT_HPP_

#include "code_allocator.hpp"

namespace dyntrace::fasttp
{
    class context;

    class arch_context
    {
    public:
        arch_context(context* ctx);

    private:
        context* _ctx;
        code_allocator<3> _pad_allocator;
        code_allocator<5> _code_allocator;
    };
}

#endif