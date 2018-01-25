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
        tracepoint(const tracepoint&) = delete;
        tracepoint& operator=(const tracepoint&) = delete;

        tracepoint(const location& loc, handler handler, const options& ops = {});
        tracepoint(tracepoint&& tp) noexcept
            : _impl{tp._impl}, _auto_remove{tp._auto_remove}
        {
            tp._impl = nullptr;
            tp._auto_remove = false;
        }
        ~tracepoint()
        {
            if(_auto_remove)
                remove();
        }

        tracepoint& operator=(tracepoint&& tp) noexcept
        {
            if(_auto_remove)
                remove();
            _impl = tp._impl;
            _auto_remove = tp._auto_remove;
            tp._impl = nullptr;
            tp._auto_remove = false;
            return *this;
        }

        void remove();

        bool auto_remove() const
        {
            return _auto_remove;
        }

        void auto_remove(bool ar)
        {
            _auto_remove = ar;
        }

    private:
        arch_tracepoint* _impl;
        bool _auto_remove;
    };
}

#endif