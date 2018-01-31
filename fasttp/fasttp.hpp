/**
 * Fast tracepoints user classes.
 */
#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include <process/process.hpp>

#include "arch/tracepoint.hpp"
#include "location.hpp"
#include "common.hpp"
#include "util/locked.hpp"
#include "util/flag.hpp"

namespace dyntrace::fasttp
{
    class tracepoint
    {
    public:
        tracepoint(const location& loc, handler handler, const options& ops = {});
        ~tracepoint();

        void enable(bool e = true) noexcept
        {
            if(e)
                _impl->enable();
            else
                _impl->disable();
        }

        void disable() noexcept
        {
            _impl->disable();
        }

        bool enabled() const noexcept
        {
            return _impl->enabled();
        }

    private:

        static std::shared_ptr<arch_tracepoint> create(const location& loc, handler&& handler, const options& ops);

        std::shared_ptr<arch_tracepoint> _impl;
    };
}

#endif