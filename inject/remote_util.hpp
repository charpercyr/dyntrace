#ifndef DYNTRACE_INJECT_REMOTE_UTIL_HPP_
#define DYNTRACE_INJECT_REMOTE_UTIL_HPP_

#include <tuple>
#include <type_traits>

namespace dyntrace::inject
{

    template<typename Target>
    class remote_ptr
    {
    public:
        remote_ptr(std::nullptr_t = nullptr) noexcept
                : _ptr{0} {}
        remote_ptr(typename Target::regval ptr) noexcept
                : _ptr{ptr} {}
        template<typename T>
        remote_ptr(T* ptr) noexcept
            : _ptr{reinterpret_cast<typename Target::regval>(ptr)} {}

        typename Target::regval get() const noexcept
        {
            return _ptr;
        }

        template<typename T>
        T* ptr() const noexcept
        {
            return reinterpret_cast<T*>(_ptr);
        }

        remote_ptr<Target> operator+(const remote_ptr<Target>& p) const noexcept
        {
            return remote_ptr{_ptr + p._ptr};
        }
        remote_ptr<Target>& operator+=(const remote_ptr<Target>& p) noexcept
        {
            _ptr += p._ptr;
            return *this;
        }

    private:
        typename Target::regval _ptr;
    };

    template<typename Target>
    struct remote_args
    {
        using type = typename Target::regval;
        type _0;
        type _1;
        type _2;
        type _3;
        type _4;
        type _5;
        type _6;
        type _7;
    };

    namespace _detail
    {

        template<typename Target, typename T>
        typename Target::regval val_to_reg(T val)
        {
            return static_cast<typename Target::regval>(val);
        };

        template<typename Target>
        typename Target::regval val_to_reg(remote_ptr<Target> val)
        {
            return val.get();
        };

        template<typename Target, typename T>
        T reg_to_val(typename Target::regval val)
        {
            return static_cast<T>(val);
        };

        template<typename Target>
        remote_ptr<Target> reg_to_val(typename Target::regval val)
        {
            return remote_ptr<Target>{val};
        }

        template<size_t N>
        struct arg_idx {};

#define __DYNTRACE_INJECT_ARG_HANDLER(idx)\
        template<typename Target>\
        void arg(remote_args<Target>& a, typename Target::regval val, arg_idx<idx>) \
        {\
            a._##idx = val;\
        }

        __DYNTRACE_INJECT_ARG_HANDLER(0);
        __DYNTRACE_INJECT_ARG_HANDLER(1);
        __DYNTRACE_INJECT_ARG_HANDLER(2);
        __DYNTRACE_INJECT_ARG_HANDLER(3);
        __DYNTRACE_INJECT_ARG_HANDLER(4);
        __DYNTRACE_INJECT_ARG_HANDLER(5);
        __DYNTRACE_INJECT_ARG_HANDLER(6);
        __DYNTRACE_INJECT_ARG_HANDLER(7);

#undef __DYNTRACE_INJECT_ARG_HANDLER
    }
}

#endif