#ifndef DYNTRACE_FASTTP_CODE_PTR_HPP_
#define DYNTRACE_FASTTP_CODE_PTR_HPP_

#include <cstdint>
#include <type_traits>

namespace dyntrace::fasttp
{
    /**
     * Represents a location in executable memory. Is explicitely castable from/to integers and pointers.
     */
    class code_ptr
    {
    public:
        code_ptr() noexcept
            : _ptr{nullptr} {}
        template<typename T>
        explicit code_ptr(T ptr) noexcept
            : _ptr{reinterpret_cast<uint8_t*>(ptr)} {}
        explicit code_ptr(std::nullptr_t) noexcept
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
        std::enable_if_t<std::is_integral_v<T>, code_ptr> operator+(T p) const noexcept
        {
            return code_ptr{_ptr + p};
        }
        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, code_ptr&> operator+=(T p) noexcept
        {
            _ptr += p;
            return *this;
        }

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, code_ptr> operator-(T p) const noexcept
        {
            return code_ptr{_ptr - p};
        }

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, code_ptr&> operator-=(T p) noexcept
        {
            _ptr -= p;
            return *this;
        }

        bool operator==(const code_ptr& ptr) const noexcept
        {
            return _ptr == ptr._ptr;
        }

        bool operator!=(const code_ptr& ptr) const noexcept
        {
            return _ptr != ptr._ptr;
        }

        bool operator<(const code_ptr& ptr) const noexcept
        {
            return _ptr < ptr._ptr;
        }

        bool operator<=(const code_ptr& ptr) const noexcept
        {
            return _ptr <= ptr._ptr;
        }

        bool operator>(const code_ptr& ptr) const noexcept
        {
            return _ptr > ptr._ptr;
        }

        bool operator>=(const code_ptr& ptr) const noexcept
        {
            return _ptr >= ptr._ptr;
        }

        explicit operator bool() const noexcept
        {
            return _ptr != nullptr;
        }

        struct hash
        {
            uintptr_t operator()(const code_ptr& ptr) const noexcept
            {
                return ptr.as_int();
            }
        };

    private:
        uint8_t* _ptr;
    };
}

#endif