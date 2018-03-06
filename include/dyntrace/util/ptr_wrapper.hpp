#ifndef DYNTRACE_UTIL_PTR_WRAPPER_HPP_
#define DYNTRACE_UTIL_PTR_WRAPPER_HPP_

#include <cstdint>
#include <type_traits>

namespace dyntrace
{
    template<typename Tag>
    class ptr_wrapper
    {
        using value_type = uint8_t*;
    public:
        ptr_wrapper() noexcept
            : _ptr{nullptr} {}
        template<typename T>
        explicit ptr_wrapper(T ptr) noexcept
            : _ptr{reinterpret_cast<value_type>(ptr)} {}
        explicit ptr_wrapper(std::nullptr_t) noexcept
            : _ptr{nullptr} {}

        /**
         * Casts to an integer or pointer.
         */
        template<typename T>
        T as() const noexcept
        {
            return reinterpret_cast<T>(_ptr);
        }

        /**
         * Casts to an unsigned integer.
         */
        uintptr_t as_int() const noexcept
        {
            return as<uintptr_t>();
        }

        /**
         * Casts to a void ptr.
         */
        void* as_ptr() const noexcept
        {
            return as<void*>();
        }

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, ptr_wrapper> operator+(T p) const noexcept
        {
            return ptr_wrapper{_ptr + p};
        }
        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, ptr_wrapper&> operator+=(T p) noexcept
        {
            _ptr += p;
            return *this;
        }

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, ptr_wrapper> operator-(T p) const noexcept
        {
            return ptr_wrapper{_ptr - p};
        }

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, ptr_wrapper&> operator-=(T p) noexcept
        {
            _ptr -= p;
            return *this;
        }

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, ptr_wrapper> operator&(T p) const noexcept
        {
            return ptr_wrapper{as_int() & p};
        };

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, ptr_wrapper&> operator&=(T p) noexcept
        {
            _ptr = reinterpret_cast<value_type>(as_int() & p);
            return *this;
        };

        bool operator==(const ptr_wrapper& ptr) const noexcept
        {
            return _ptr == ptr._ptr;
        }

        bool operator!=(const ptr_wrapper& ptr) const noexcept
        {
            return _ptr != ptr._ptr;
        }

        bool operator<(const ptr_wrapper& ptr) const noexcept
        {
            return _ptr < ptr._ptr;
        }

        bool operator<=(const ptr_wrapper& ptr) const noexcept
        {
            return _ptr <= ptr._ptr;
        }

        bool operator>(const ptr_wrapper& ptr) const noexcept
        {
            return _ptr > ptr._ptr;
        }

        bool operator>=(const ptr_wrapper& ptr) const noexcept
        {
            return _ptr >= ptr._ptr;
        }

        explicit operator bool() const noexcept
        {
            return _ptr != nullptr;
        }

        struct hash
        {
            uintptr_t operator()(const ptr_wrapper& ptr) const noexcept
            {
                return ptr.as_int();
            }
        };

    private:
        value_type _ptr;
    };
}

#endif