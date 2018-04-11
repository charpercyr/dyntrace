#ifndef DYNTRACE_TRACER_HPP_
#define DYNTRACE_TRACER_HPP_

#include "dyntrace/arch/arch.hpp"

#include <exception>
#include <functional>
#include <variant>

namespace dyntrace::tracer
{
    struct tracer_error : std::runtime_error
    {
        tracer_error(std::string tracer, std::string msg)
            : std::runtime_error{tracer + ": " + msg}{}
    };

    using point_handler = std::function<void(const void*, const dyntrace::arch::regs&)>;
    using entry_exit_handler = std::tuple<point_handler, point_handler>;
    using handler = std::variant<point_handler, entry_exit_handler>;

    namespace _detail
    {
        template<typename Tuple, typename Func, size_t...Ints>
        point_handler unpack_regs(Func&& func, std::index_sequence<Ints...>) noexcept
        {
            return point_handler{
                [func = std::forward<Func>(func)](const void *caller, const dyntrace::arch::regs &regs) -> void
                {
                    func(caller, dyntrace::arch::arg<std::tuple_element_t<Ints, Tuple>>(regs, Ints)...);
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
}

#endif