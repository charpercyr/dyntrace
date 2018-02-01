/**
 * Fast tracepoints user classes.
 */
#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include "arch/tracepoint.hpp"
#include "common.hpp"
#include "location.hpp"

namespace dyntrace::fasttp
{
    /**
     * Moveable handle for an arch_tracepoint.
     * This object controls the lifetime of the tracepoint.
     */
    class tracepoint
    {
    public:
        tracepoint(const fasttp::location& loc, handler handler, const options& ops = {});

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

        const void* location() const noexcept
        {
            return _impl->location();
        }

    private:
        std::unique_ptr<arch_tracepoint> _impl;
    };
}

#endif