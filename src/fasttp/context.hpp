#ifndef DYNTRACE_FASTTP_CONTEXT_HPP_
#define DYNTRACE_FASTTP_CONTEXT_HPP_

#include "reclaimer.hpp"

#include "dyntrace/process/process.hpp"
#include "dyntrace/util/locked.hpp"

namespace dyntrace::fasttp
{
    class arch_context;
    /**
     * Singleton that contains all the process-global data.
     */
    class context
    {
    public:
        static context& instance() noexcept;

        arch_context& arch() noexcept
        {
            return *_impl;
        }

        const arch_context& arch() const noexcept
        {
            return *_impl;
        }

    private:
        context() noexcept;

        std::unique_ptr<arch_context> _impl;
    };
}

#endif