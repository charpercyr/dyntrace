/**
 * Common classes for fasttp
 */
#ifndef DYNTRACE_FASTTP_OPTIONS_HPP_
#define DYNTRACE_FASTTP_OPTIONS_HPP_

#include "dyntrace/tracer.hpp"

namespace dyntrace
{
    namespace fasttp
    {
        using point_handler = dyntrace::tracer::point_handler;
        using entry_exit_handler = dyntrace::tracer::entry_exit_handler;
        using handler = dyntrace::tracer::handler;

        using addr_location = void*;
        using symbol_location = std::string;
        using location = std::variant<addr_location, symbol_location>;

        inline location make_location(addr_location loc)
        {
            return loc;
        }

        template<typename R, typename...Args>
        inline location make_location(R(*loc)(Args...))
        {
            return reinterpret_cast<void*>(loc);
        }

        inline location make_location(symbol_location loc)
        {
            return loc;
        }

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