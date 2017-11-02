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
        explicit remote_ptr(typename Arch::regval ptr = {}) noexcept
                : _ptr{ptr} {}

        template<typename T = void>
        T* ptr() const noexcept
        {
            return reinterpret_cast<T*>(_ptr);
        }

        typename Arch::regval get() const noexcept
        {
            return _ptr;
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
        void arg(typename Arch::regs& r, typename Arch::regval val);
    }
}

#endif