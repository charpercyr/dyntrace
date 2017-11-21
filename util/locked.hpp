#ifndef DYNTRACE_UTIL_LOCKED_HPP_
#define DYNTRACE_UTIL_LOCKED_HPP_

#include <mutex>

namespace dyntrace
{
    template<typename T, typename Lock>
    class locked_proxy
    {
        template<typename, typename>
        friend class locked_proxy;
    public:
        locked_proxy(T* t, Lock& lock)
                : _t{t}, _guard{lock} {}

        T& operator*() noexcept
        {
            return *_t;
        }
        const T& operator*() const noexcept
        {
            return *_t;
        }

        T* operator->() noexcept
        {
            return _t;
        }
        const T* operator->() const noexcept
        {
            return _t;
        }

        T* get() noexcept
        {
            return _t;
        }
        const T* get() const noexcept
        {
            return _t;
        }

        template<typename U>
        auto lock_for(U* u)
        {
            return locked_proxy<U, Lock>{u, std::move(_guard)};
        }

        operator bool() const noexcept
        {
            return _t != nullptr;
        }

    private:
        locked_proxy(T* val, std::unique_lock<Lock>&& guard)
            : _t{val}, _guard{std::move(guard)} {}

        T* _t;
        mutable std::unique_lock<Lock> _guard;
    };

    template<typename T, typename Lock=std::mutex>
    class locked
    {
    public:

        template<typename...Args>
        explicit locked(Args&&...args) noexcept(std::is_nothrow_constructible_v<T, Args...>)
        : _val{std::forward<Args>(args)...} {}

        locked(const locked<T, Lock>&) = delete;
        locked(locked<T, Lock>&&) = delete;
        locked<T, Lock>& operator=(const locked<T, Lock>&) = delete;
        locked<T, Lock>& operator=(locked<T, Lock>&&) = delete;

        locked_proxy<T, Lock> lock()
        {
            return locked_proxy<T, Lock>(&_val, _lock);
        };
        locked_proxy<const T, Lock> lock() const
        {
            return locked_proxy<const T, Lock>(&_val, _lock);
        };

        const T& operator*() const
        {
            return _val;
        }
        const T* operator->() const
        {
            return &_val;
        }

    private:
        T _val;
        mutable Lock _lock;
    };
}

#endif