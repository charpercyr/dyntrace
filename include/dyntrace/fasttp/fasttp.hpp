/**
 * Fast tracepoints user classes.
 */
#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include "common.hpp"

#include <memory>

namespace dyntrace::fasttp
{
    class arch_tracepoint;
    /**
     * Moveable handle for an arch_tracepoint.
     * This object controls the lifetime of the tracepoint.
     */
    class tracepoint
    {
    public:
        tracepoint(const tracepoint&) = delete;
        tracepoint& operator=(const tracepoint&) = delete;

        tracepoint() noexcept
            : _impl{nullptr} {}
        tracepoint(void* loc, handler handler, const options& ops = {});
        tracepoint(tracepoint&& tp) noexcept
            : _impl{tp._impl}
        {
            tp._impl = nullptr;
        }
        tracepoint& operator=(tracepoint&& tp);
        ~tracepoint();

        void enable(bool e = true) noexcept;
        void disable() noexcept;
        bool enabled() const noexcept;
        const void* location() const noexcept;

        explicit operator bool() const noexcept
        {
            return static_cast<bool>(_impl);
        }

    private:
        arch_tracepoint* _impl;
    };
}

#endif