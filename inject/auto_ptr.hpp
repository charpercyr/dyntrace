#ifndef DYNTRACE_INJECT_AUTO_PTR_HPP_
#define DYNTRACE_INJECT_AUTO_PTR_HPP_

#include <cstddef>

#include "remote_util.hpp"

#include <functional>
#include <memory>

namespace dyntrace::inject
{
    template<typename Target>
    class remote_auto_ptr
    {
    public:
        remote_auto_ptr(remote_ptr<Target> ptr, std::function<void(remote_ptr<Target>)> del)
            : _ptr{ptr}, _del{std::move(del)} {}
        ~remote_auto_ptr()
        {
            if(_ptr)
            {
                _del(_ptr);
            }
        }

        remote_auto_ptr(const remote_auto_ptr<Target>&) = default;
        remote_auto_ptr(remote_auto_ptr<Target>&& ptr) noexcept
            : _ptr{ptr._ptr}, _del{std::move(ptr._del)}
        {
            ptr._ptr = 0;

        }

        remote_auto_ptr<Target>& operator=(const remote_auto_ptr<Target>&) = default;
        remote_auto_ptr<Target>& operator=(remote_auto_ptr<Target>&& ptr) noexcept
        {
            _ptr = ptr._ptr;
            _del = std::move(ptr._del);
            ptr._ptr = 0;
            return *this;
        }

        template<typename T>
        T* ptr() const noexcept
        {
            return _ptr.template ptr<T>();
        }

        operator remote_ptr<Target>() const noexcept
        {
            return _ptr;
        }

        remote_ptr<Target> get() const noexcept
        {
            return _ptr;
        }

    private:
        remote_ptr<Target> _ptr;
        std::function<void(remote_ptr<Target>)> _del;
    };
}

#endif