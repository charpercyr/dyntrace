/**
 * Adds flag operators and check for an enum type
 */

#ifndef DYNTRACE_UTIL_FLAG_HPP_
#define DYNTRACE_UTIL_FLAG_HPP_

#include <type_traits>

namespace dyntrace
{
    template<typename E>
    struct is_flag_enum : std::false_type {};
    template<typename E>
    constexpr bool is_flag_enum_v = is_flag_enum<E>::value;
    template<typename E, typename T>
    using enable_if_flag_enum_t = std::enable_if_t<is_flag_enum_v<E>, T>;

    template<typename E>
    constexpr enable_if_flag_enum_t<E, E> operator|(E e1, E e2) noexcept
    {
        using I = typename std::underlying_type<E>::type;
        return static_cast<E>(static_cast<I>(e1) | static_cast<I>(e2));
    }

    template<typename E>
    constexpr enable_if_flag_enum_t<E, E> operator&(E e1, E e2) noexcept
    {
        using I = typename std::underlying_type<E>::type;
        return static_cast<E>(static_cast<I>(e1) & static_cast<I>(e2));
    }

    template<typename E>
    constexpr enable_if_flag_enum_t<E, E&> operator|=(E& e1, E e2) noexcept
    {
        return (e1 = e1 | e2);
    }

    template<typename E>
    constexpr enable_if_flag_enum_t<E, E&> operator&=(E& e1, E e2) noexcept
    {
        return (e1 = e1 & e2);
    }

    template<typename E>
    constexpr enable_if_flag_enum_t<E, bool> flag(E e, E f) noexcept
    {
        using I = typename std::underlying_type<E>::type;
        return static_cast<I>(e & f) != 0;
    }
}

#endif