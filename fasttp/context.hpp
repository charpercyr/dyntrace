#ifndef DYNTRACE_FASTTP_CONTEXT_HPP_
#define DYNTRACE_FASTTP_CONTEXT_HPP_

#include "arch/tracepoint.hpp"
#include "location.hpp"
#include "reclaimer.hpp"

#include <process/process.hpp>
#include <util/locked.hpp>

namespace dyntrace::fasttp
{
    /**
     * Singleton that contains all the process-global data.
     */
    class context
    {
    public:
        static context& instance() noexcept;

        arch_context& arch() noexcept
        {
            return _impl;
        }

        const arch_context& arch() const noexcept
        {
            return _impl;
        }

        reclaimer& get_reclaimer() noexcept
        {
            return _reclaimer;
        }

    private:
        context() noexcept;

        arch_context _impl;
        reclaimer _reclaimer;
    };
}

#endif