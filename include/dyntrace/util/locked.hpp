/**
 * Class that wraps an object and a lock. To use the object, one must lock it beforehand.
 */

#ifndef DYNTRACE_UTIL_LOCKED_HPP_
#define DYNTRACE_UTIL_LOCKED_HPP_

#include <atomic>
#include <mutex>
#include <shared_mutex>

namespace dyntrace
{
    struct nolock
    {
        void lock() noexcept
        {
            std::atomic_thread_fence(std::memory_order_acquire);
        }
        bool try_lock() noexcept
        {
            std::atomic_thread_fence(std::memory_order_acquire);
            return true;
        }
        void unlock() noexcept
        {
            std::atomic_thread_fence(std::memory_order_release);
        }

        void lock_shared() noexcept
        {
            std::atomic_thread_fence(std::memory_order_acquire);
        }
        bool try_lock_shared() noexcept
        {
            std::atomic_thread_fence(std::memory_order_acquire);
            return true;
        }
        void unlock_shared() noexcept
        {
            std::atomic_thread_fence(std::memory_order_release);
        }
    };
    /**
     * Proxy that represents a locked object. The lock is locked during the lifetime of this object.
     */
    template<typename T, typename Lock, typename Guard>
    class [[nodiscard]] locked_proxy
    {
        template<typename, typename, typename>
        friend class locked_proxy;
    public:
        using value_type = T;
        using lock_type = Lock;
        using guard_type = Guard;

        locked_proxy(value_type* val, lock_type& lock) noexcept
                : _val{val}, _guard{val ? guard_type{lock} : guard_type{}} {}

        value_type& operator*() noexcept
        {
            return *_val;
        }
        const value_type& operator*() const noexcept
        {
            return *_val;
        }

        value_type* operator->() noexcept
        {
            return _val;
        }
        const value_type* operator->() const noexcept
        {
            return _val;
        }

        value_type* get() noexcept
        {
            return _val;
        }
        const value_type* get() const noexcept
        {
            return _val;
        }

        explicit operator bool() const noexcept
        {
            return _val != nullptr;
        }

        void unlock() noexcept
        {
            _guard.unlock();
            _val = nullptr;
        }

    private:
        locked_proxy(T* val, guard_type&& guard)
            : _val{val}, _guard{std::move(guard)} {}

        value_type* _val;
        guard_type _guard;
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
        using value_type = T;
        using lock_type = Lock;
        using locked_type = locked<value_type, lock_type>;
        using proxy_type = locked_proxy<value_type, lock_type, std::unique_lock<lock_type>>;
        using const_proxy_type = locked_proxy<const value_type, lock_type, std::unique_lock<lock_type>>;
        using shared_proxy_type = locked_proxy<const value_type, lock_type, std::shared_lock<lock_type>>;

        template<typename...Args>
        locked(Args&&...args) noexcept(std::is_nothrow_constructible_v<T, Args...>)
            : _val{std::forward<Args>(args)...} {}

        locked(const locked_type&) = delete;
        locked(locked_type&&) = delete;
        locked_type& operator=(const locked_type&) = delete;
        locked_type& operator=(locked_type&&) = delete;

        /**
         * Obtains a locked proxy. The object can now be used safely.
         * @return
         */
        proxy_type lock()
        {
            return proxy_type{&_val, _lock};
        };
        /**
         * Obtains a const locked proxy. The object can now be used safely.
         * @return
         */
        const_proxy_type lock() const
        {
            return const_proxy_type{&_val, _lock};
        };

        /**
         * Obtains a const shared locked proxy. Multiple readers are ok.
         * @return
         */
        shared_proxy_type lock_shared() const
        {
            return shared_proxy_type{&_val, _lock};
        }

        /**
         * Const accessors for the object since const (should) be thread-safe.
         */
        const value_type& operator*() const
        {
            return _val;
        }
        /**
         * Const accessors for the object since const (should) be thread-safe.
         */
        const value_type* operator->() const
        {
            return &_val;
        }

    private:
        value_type _val;
        mutable lock_type _lock;
    };
    template<typename T>
    using unique_locked = locked<T, std::mutex>;
    template<typename T>
    using shared_locked = locked<T, std::shared_mutex>;
    template<typename T>
    using nolock_locked = locked<T, nolock>;
}

#endif