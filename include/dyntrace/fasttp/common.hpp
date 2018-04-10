/**
 * Common classes for fasttp
 */
#ifndef DYNTRACE_FASTTP_OPTIONS_HPP_
#define DYNTRACE_FASTTP_OPTIONS_HPP_

#include <string>

#include "dyntrace/tracer.hpp"

namespace dyntrace
{
    namespace fasttp
    {
        using point_handler = dyntrace::tracer::point_handler;
        using entry_exit_handler = dyntrace::tracer::entry_exit_handler;
        using handler = dyntrace::tracer::handler;

        inline void* resolve(void *loc)
        {
            return loc;
        }

        inline void* resolve(uintptr_t loc)
        {
            return reinterpret_cast<void*>(loc);
        }

        template<typename R, typename...Args>
        inline void* resolve(R(*loc)(Args...))
        {
            return reinterpret_cast<void*>(loc);
        }

        void* resolve(const std::string& loc);

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