#ifndef DYNTRACE_TRACERS_LIB_TRACER_HPP_
#define DYNTRACE_TRACERS_LIB_TRACER_HPP_

#ifdef __x86_64__
#include "x86_64.hpp"
#else
#error "Architecture not supported"
#endif

namespace dyntrace::tracer
{
    namespace _detail
    {
        template<typename T>
        constexpr std::enable_if_t<std::is_integral_v<T>, T> cast(regs::uint v) noexcept
        {
            return static_cast<T>(v);
        };

        template<typename T>
        constexpr std::enable_if_t<std::is_pointer_v<T>, T> cast(regs::uint v) noexcept
        {
            return reinterpret_cast<T>(v);
        };
    }

    template<size_t N, typename T = regs::uint>
    inline T arg(const regs& r) noexcept
    {
        return _detail::cast<T>(r.arg<N>());
    }

    template<typename T = regs::uint>
    inline T ret(const regs& r) noexcept
    {
        return _detail::cast<T>(r.ret());
    }

    inline regs::uint* return_address(const regs& r) noexcept
    {
        return reinterpret_cast<regs::uint*>(r.return_address());
    }

    inline regs::uint* stack(const regs& r) noexcept
    {
        return reinterpret_cast<regs::uint*>(r.stack());
    }
}

#endif