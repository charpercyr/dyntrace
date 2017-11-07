#ifndef DYNTRACE_INJECT_REMOTE_UTIL_HPP_
#define DYNTRACE_INJECT_REMOTE_UTIL_HPP_

#include <tuple>
#include <type_traits>

namespace dyntrace::inject
{

    template<typename>
    class ptrace;

    template<typename Arch>
    class remote_ptr
    {
    public:
        remote_ptr(typename Arch::regval ptr = {}) noexcept
            : _ptr{ptr} {}
        template<typename T>
        remote_ptr(T* ptr) noexcept
            : _ptr{reinterpret_cast<typename Arch::regval>(ptr)} {}
        remote_ptr(nullptr_t) noexcept
            : _ptr{0} {}

        typename Arch::regval get() const noexcept
        {
            return _ptr;
        }

        template<typename T>
        T* ptr() const noexcept
        {
            return reinterpret_cast<T*>(_ptr);
        }

        remote_ptr<Arch> operator+(const remote_ptr<Arch>& p) const noexcept
        {
            return remote_ptr{_ptr + p._ptr};
        }
        remote_ptr<Arch>& operator+=(const remote_ptr<Arch>& p) noexcept
        {
            _ptr += p._ptr;
            return *this;
        }

    private:
        typename Arch::regval _ptr;
    };

    namespace _detail
    {
        template<typename Arch, typename T>
        typename Arch::regval val_to_reg(T val)
        {
            return static_cast<typename Arch::regval>(val);
        };

        template<typename Arch>
        typename Arch::regval val_to_reg(remote_ptr<Arch> val)
        {
            return val.get();
        };

        template<typename Arch, typename T>
        T reg_to_val(typename Arch::regval val)
        {
            return static_cast<T>(val);
        };

        template<typename Arch>
        remote_ptr<Arch> reg_to_val(typename Arch::regval val)
        {
            return remote_ptr<Arch>{val};
        }

        template<typename Arch, size_t N>
        void arg(typename Arch::args& r, typename Arch::regval val);
    }
}

#endif