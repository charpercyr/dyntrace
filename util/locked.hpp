/**
 * Class that wraps an object and a lock. To use the object, one must lock it beforehand.
 */

#ifndef DYNTRACE_UTIL_LOCKED_HPP_
#define DYNTRACE_UTIL_LOCKED_HPP_

#include <mutex>

namespace dyntrace
{
    /**
     * Proxy that represents a locked object. The lock is locked during the lifetime of this object.
     */
    template<typename T, typename Lock>
    class locked_proxy
    {
        template<typename, typename>
        friend class locked_proxy;
    public:
        locked_proxy(T* t, Lock& lock) noexcept
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

        /**
         * Moves the lock to a subobject. The lock is going to be owned by the subobject's proxy.
         */
        template<typename U>
        auto lock_for(U* u)
        {
            _t = nullptr;
            return locked_proxy<U, Lock>{u, std::move(_guard)};
        }

        explicit operator bool() const noexcept
        {
            return _t != nullptr;
        }

    private:
        locked_proxy(T* val, std::unique_lock<Lock>&& guard)
            : _t{val}, _guard{std::move(guard)} {}

        T* _t;
        std::unique_lock<Lock> _guard;
    };

    /**
     * Lock wrapper for an object. Also acts
     * @tparam T The type of the object
     * @tparam Lock The type of the lock (must be BasicLockable)
     */
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

        /**
         * Obtains a locked proxy. The object can now be used safely.
         * @return
         */
        locked_proxy<T, Lock> lock()
        {
            return locked_proxy<T, Lock>(&_val, _lock);
        };
        /**
         * Obtains a const locked proxy. The object can now be used safely.
         * @return
         */
        locked_proxy<const T, Lock> lock() const
        {
            return locked_proxy<const T, Lock>(&_val, _lock);
        };

        /**
         * Const accessors for the object since const (should) be thread-safe.
         */
        const T& operator*() const
        {
            return _val;
        }
        /**
         * Const accessors for the object since const (should) be thread-safe.
         */
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