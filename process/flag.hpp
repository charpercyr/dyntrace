#ifndef DYNTRACE_PROCESS_FLAG_HPP_
#define DYNTRACE_PROCESS_FLAG_HPP_

#include <type_traits>

namespace dyntrace::process
{
    template<typename E>
    struct is_flag_enum : std::false_type {};

#define __ENABLE_IF_FLAG_ENUM(E, R) \
    typename std::enable_if<is_flag_enum<E>::value, R>::type

    template<typename E>
    constexpr __ENABLE_IF_FLAG_ENUM(E, E) operator|(E e1, E e2) noexcept
    {
        using I = typename std::underlying_type<E>::type;
        return static_cast<E>(static_cast<I>(e1) | static_cast<I>(e2));
    }

    template<typename E>
    constexpr __ENABLE_IF_FLAG_ENUM(E, E) operator&(E e1, E e2) noexcept
    {
        using I = typename std::underlying_type<E>::type;
        return static_cast<E>(static_cast<I>(e1) & static_cast<I>(e2));
    }

    template<typename E>
    constexpr __ENABLE_IF_FLAG_ENUM(E, E&) operator|=(E& e1, E e2) noexcept
    {
        return (e1 = e1 | e2);
    }

    template<typename E>
    constexpr __ENABLE_IF_FLAG_ENUM(E, E&) operator&=(E& e1, E e2) noexcept
    {
        return (e1 = e1 & e2);
    }

    template<typename E>
    constexpr __ENABLE_IF_FLAG_ENUM(E, bool) flag(E e, E f) noexcept
    {
        using I = typename std::underlying_type<E>::type;
        return static_cast<I>(e & f) != 0;
    }

#undef __ENABLE_IF_FLAG_ENUM
}

#endif