/**
 * Common classes for fasttp
 */
#ifndef DYNTRACE_FASTTP_OPTIONS_HPP_
#define DYNTRACE_FASTTP_OPTIONS_HPP_

#include "dyntrace/tracer.hpp"

#include <functional>
#include <tuple>
#include <variant>

namespace dyntrace
{
    namespace fasttp
    {
        using point_handler = dyntrace::tracer::point_handler;
        using entry_exit_handler = dyntrace::tracer::entry_exit_handler;
        using handler = dyntrace::tracer::handler;

        /**
         * Tracepoint options.
         */
        struct options
        {
            /// x86(_64) specific options.
            struct
            {
                bool disable_thread_safe{false};
                point_handler trap_handler{nullptr};
            } x86;
        };
    }
}

#endif