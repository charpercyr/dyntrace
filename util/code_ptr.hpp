#ifndef DYNTRACE_UTIL_CODE_PTR_HPP_
#define DYNTRACE_UTIL_CODE_PTR_HPP_

#include <stdint.h>

namespace dyntrace
{
    class code_ptr
    {
    public:
        code_ptr() noexcept = default;
        template<typename T>
        code_ptr(T ptr)
            : _ptr{reinterpret_cast<uint8_t*>(ptr)} {}

        template<typename T = void*>
        T as() const noexcept
        {
            return reinterpret_cast<T>(_ptr);
        }

        operator void*() const noexcept
        {
            return as();
        }

        uintptr_t as_int() const noexcept
        {
            return as<uintptr_t>();
        }

        void* as_ptr() const noexcept
        {
            return as();
        }

        code_ptr operator+(uintptr_t i) noexcept
        {
            return code_ptr{_ptr + i};
        }
        code_ptr& operator+=(uintptr_t i) noexcept
        {
            return *this = *this + i;
        }

        bool operator==(const code_ptr& ptr) const noexcept
        {
            return _ptr == ptr._ptr;
        }

        bool operator==(void* ptr) const noexcept
        {
            return _ptr == ptr;
        }

        bool operator!=(const code_ptr& ptr) const noexcept
        {
            return _ptr != ptr._ptr;
        }

        bool operator!=(void* ptr) const noexcept
        {
            return _ptr != ptr;
        }

    private:
        uint8_t* _ptr{nullptr};
    };
}

#endif