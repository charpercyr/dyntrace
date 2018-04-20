#ifndef DYNTRACE_FASSTP_ARCH_ARM_CONTEXT_HPP_
#define DYNTRACE_FASSTP_ARCH_ARM_CONTEXT_HPP_

#include "code_allocator.hpp"

#include "dyntrace/util/locked.hpp"

namespace dyntrace::fasttp
{
    class context;

    class arch_context
    {
    public:
        using pad_allocator = dyntrace::fasttp::code_allocator<3>;
        using code_allocator = dyntrace::fasttp::code_allocator<5>;
        arch_context(context* ctx);

        auto pad_alloc()
        {
            return _pad_alloc.lock();
        }

        auto code_alloc()
        {
            return _code_alloc.lock();
        }

        context* get_context()
        {
            return _ctx;
        }

    private:
        context* _ctx;
        locked<pad_allocator> _pad_alloc;
        locked<code_allocator> _code_alloc;
    };
}

#endif