#ifndef DYNTRACE_FASTTP_OPTIONS_HPP_
#define DYNTRACE_FASTTP_OPTIONS_HPP_

#include <arch/arch.hpp>

#include <functional>
#include <tuple>

namespace dyntrace
{
    namespace fasttp
    {
        using handler = std::function<void(const void*, const arch::regs&)>;

        namespace _detail
        {
            template<typename Tuple, typename Func, size_t...Ints>
            handler unpack_regs(Func&& func, std::index_sequence<Ints...>)
            {
                return handler{
                    [func = std::forward<Func>(func)](const void *caller, const arch::regs &regs) -> void
                    {
                        func(caller, arch::arg<std::tuple_element_t<Ints, Tuple>>(regs, Ints)...);
                    }
                };
            };
        }

        template<typename...Args>
        handler make_handler(std::function<void(const void*, Args...)>&& func)
        {
            return _detail::unpack_regs<std::tuple<Args...>>(std::move(func), std::index_sequence_for<Args...>{});
        }

        struct common
        {
            bool disable_auto_remove{false};
            struct
            {
                bool disable_jmp_safe{false};
                bool disable_thread_safe{false};
                handler trap_handler{nullptr};
            } x86;
        };
    }
}

#endif