#ifndef DYNTRACE_FASTTP_CONTEXT_HPP_
#define DYNTRACE_FASTTP_CONTEXT_HPP_

#include <process/process.hpp>
#include <util/locked.hpp>

#include "arch/tracepoint.hpp"
#include "location.hpp"
#include "reclaimer.hpp"

namespace dyntrace::fasttp
{
    class context
    {
    public:
        static context& instance();

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
        context();

        arch_context _impl;
        dyntrace::locked<std::unordered_map<void*, std::unique_ptr<arch_tracepoint>>> _tracepoints;
        reclaimer _reclaimer;
    };
}

#endif