#ifndef DYNTRACE_FASTTP_ARCH_POWERPC_CONTEXT_HPP_
#define DYNTRACE_FASTTP_ARCH_POWERPC_CONTEXT_HPP_

#include "../../code_allocator.hpp"

#include "dyntrace/util/locked.hpp"

namespace dyntrace::fasttp
{
    class context;

    class arch_context
    {
    public:
        using allocator_type = code_allocator<5>;
        arch_context(context*) {}

        auto get_alloc()
        {
            return _alloc.lock();
        }

        auto get_context() const
        {
            return _ctx;
        }

    private:
        context* _ctx;
        locked<allocator_type> _alloc;
    };
}

#endif