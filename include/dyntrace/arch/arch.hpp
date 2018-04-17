/**
 * Arhitecture specific register utility functions.
 */
#ifndef DYNTRACE_ARCH_ARCH_HPP_
#define DYNTRACE_ARCH_ARCH_HPP_

#if defined(__i386__) || defined(__x86_64__)
#include "x86.hpp"
#elif defined(__arm__)
#include "arm.hpp"
#else
#error "Architecture not supported"
#endif

#include <type_traits>

namespace dyntrace::arch
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

        template<typename T>
        constexpr std::enable_if_t<std::is_reference_v<T>, T> cast(regs::uint v) noexcept
        {
            return *reinterpret_cast<std::remove_reference_t<T>*>(v);
        };
    }

    /**
     * Gets an argument for a function call. Usually works only if the tracepoint is the first instruction.
     * @tparam T Type to cast the word to.
     * @param r The registers.
     * @param i The index of the argument.
     */
    template<typename T = regs::uint>
    inline const T arg(const regs& r, size_t i) noexcept
    {
        return _detail::cast<T>(r.arg(i));
    }

    /**
     * Gets the return value of a function call. Usually works only if the tracepoint is a return trampoline.
     * @tparam T Type to cast the word to.
     * @param r The registers.
     */
    template<typename T = regs::uint>
    inline const T ret(const regs& r) noexcept
    {
        return _detail::cast<T>(r.ret());
    }

    /**
     * Gets the return address of the function. Usually works only if the tracepoint is the first instruction.
     * @param r The registers.
     */
    inline const void* return_address(const regs& r) noexcept
    {
        return reinterpret_cast<const void*>(r.return_address());
    }

    /**
     * Gets the current stack top
     * @param r The registers.
     */
    inline const void* stack(const regs& r) noexcept
    {
        return reinterpret_cast<const void*>(r.stack());
    }
}

#endif