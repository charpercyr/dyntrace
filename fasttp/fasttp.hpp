/**
 * Fast tracepoints user classes.
 */
#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include "arch/tracepoint.hpp"
#include "location.hpp"
#include "common.hpp"

namespace dyntrace::fasttp
{
    class tracepoint
    {
    public:
        tracepoint(const location& loc, handler handler, const options& ops = {});

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
        std::unique_ptr<arch_tracepoint> _impl;
    };
}

#endif