/**
 * Common classes for fasttp
 */
#ifndef DYNTRACE_FASTTP_OPTIONS_HPP_
#define DYNTRACE_FASTTP_OPTIONS_HPP_

#include "dyntrace/arch/arch.hpp"

#include <functional>
#include <tuple>
#include <variant>

namespace dyntrace
{
    namespace fasttp
    {
        using point_handler = std::function<void(const void*, const arch::regs&)>;
        using enter_exit_handler = std::tuple<point_handler, point_handler>;
        using handler = std::variant<point_handler, enter_exit_handler>;

        namespace _detail
        {
            template<typename Tuple, typename Func, size_t...Ints>
            point_handler unpack_regs(Func&& func, std::index_sequence<Ints...>) noexcept
            {
                return point_handler{
                    [func = std::forward<Func>(func)](const void *caller, const arch::regs &regs) -> void
                    {
                        func(caller, arch::arg<std::tuple_element_t<Ints, Tuple>>(regs, Ints)...);
                    }
                };
            };
        }

        /**
         * Creates a handler from some function. It will map the arguments of the traced function to the handler.
         */
        template<typename...Args>
        point_handler make_point_handler(std::function<void(const void *, Args...)> func)
        {
            return _detail::unpack_regs<std::tuple<Args...>>(std::move(func), std::index_sequence_for<Args...>{});
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