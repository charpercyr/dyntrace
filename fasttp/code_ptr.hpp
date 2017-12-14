#ifndef DYNTRACE_FASTTP_CODE_PTR_HPP_
#define DYNTRACE_FASTTP_CODE_PTR_HPP_

#include <cstdint>
#include <type_traits>

namespace dyntrace::fasttp
{
    class code_ptr
    {
    public:
        code_ptr() noexcept = default;
        template<typename T>
        code_ptr(T ptr)
            : _ptr{reinterpret_cast<uint8_t*>(ptr)} {}
        code_ptr(std::nullptr_t)
            : _ptr{nullptr} {}

        template<typename T>
        T as() const noexcept
        {
            return reinterpret_cast<T>(_ptr);
        }

        uintptr_t as_int() const noexcept
        {
            return as<uintptr_t>();
        }

        void* as_ptr() const noexcept
        {
            return as<void*>();
        }

        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, code_ptr> operator+(T p) noexcept
        {
            return code_ptr{_ptr + p};
        }
        template<typename T>
        std::enable_if_t<std::is_integral_v<T>, code_ptr&> operator+=(T p) noexcept
        {
            return *this = *this + p;
        }

        bool operator==(const code_ptr& ptr) const noexcept
        {
            return _ptr == ptr._ptr;
        }

        bool operator!=(const code_ptr& ptr) const noexcept
        {
            return _ptr != ptr._ptr;
        }

        operator bool() const noexcept
        {
            return _ptr != nullptr;
        }

    private:
        uint8_t* _ptr{nullptr};
    };
}

#endif