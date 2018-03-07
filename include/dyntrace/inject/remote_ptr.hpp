#ifndef DYNTRACE_INJECT_REMOTE_PTR_HPP_
#define DYNTRACE_INJECT_REMOTE_PTR_HPP_

#include "dyntrace/util/ptr_wrapper.hpp"

#include <functional>

namespace dyntrace::inject
{
    struct remote_ptr_tag;
    using remote_ptr = dyntrace::ptr_wrapper<remote_ptr_tag>;

    struct unique_remote_ptr
    {
    public:
        using deleter = std::function<void(remote_ptr)>;

        unique_remote_ptr(const unique_remote_ptr&) = delete;
        unique_remote_ptr& operator=(const unique_remote_ptr&) = delete;

        unique_remote_ptr() = default;
        unique_remote_ptr(remote_ptr ptr, deleter del) noexcept
            : _ptr{ptr}, _del{std::move(del)} {}
        unique_remote_ptr(unique_remote_ptr&& ptr) noexcept
            : _ptr{ptr._ptr}, _del{std::move(ptr._del)}
        {
            ptr._ptr = {};
        }
        unique_remote_ptr& operator=(unique_remote_ptr&& ptr) noexcept
        {
            if(_ptr)
                _del(_ptr);
            _ptr = ptr._ptr;
            _del = std::move(ptr._del);
            ptr._ptr = {};
            return *this;
        }
        ~unique_remote_ptr()
        {
            if(_ptr)
                _del(_ptr);
        }

        template<typename T>
        T as() const noexcept
        {
            return _ptr.as<T>();
        }

        void* as_ptr() const noexcept
        {
            return _ptr.as_ptr();
        }

        remote_ptr get() const noexcept
        {
            return _ptr;
        }

        uintptr_t as_int() const noexcept
        {
            return _ptr.as_int();
        }

        explicit operator bool() const noexcept
        {
            return _ptr.operator bool();
        }

    private:
        remote_ptr _ptr;
        deleter _del;
    };
}

#endif