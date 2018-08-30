#ifndef DYNTRACE_UTIL_REFCNT_HPP_
#define DYNTRACE_UTIL_REFCNT_HPP_

#include <atomic>
#include <utility>

namespace dyntrace
{

    template<typename T>
    class refcnt_ptr
    {
        template<typename>
        friend
        class refcnt_ptr;

        template<typename U>
        static constexpr bool is_compatible = std::is_convertible_v<U *, T *>;
        template<typename U, typename R = void>
        using enable_if_compatible = std::enable_if_t<is_compatible<U>, R>;

        static constexpr bool is_nothrow_acquire = noexcept(std::declval<T *>()->acquire());
        static constexpr bool is_nothrow_release = noexcept(std::declval<T *>()->release());
    public:

        ~refcnt_ptr() noexcept(is_nothrow_release)
        {
            release();
        }

        refcnt_ptr() noexcept
            : _ptr{nullptr}
        {}

        explicit refcnt_ptr(std::nullptr_t) noexcept
            : _ptr{nullptr}
        {}

        template<typename U, typename = enable_if_compatible<U>>
        explicit refcnt_ptr(U *p) noexcept(is_nothrow_acquire)
            : _ptr{p}
        {
            acquire();
        }

        refcnt_ptr(const refcnt_ptr &ptr) noexcept(is_nothrow_acquire)
            : _ptr{ptr._ptr}
        {
            acquire();
        }
        template<typename U, typename = enable_if_compatible<U>>
        refcnt_ptr(const refcnt_ptr<U>& ptr) noexcept(is_nothrow_acquire)
            : _ptr{ptr._ptr}
        {
            acquire();
        }
        refcnt_ptr(refcnt_ptr&& ptr) noexcept
            : _ptr{ptr._ptr}
        {
            ptr._ptr = nullptr;
        }
        template<typename U, typename = enable_if_compatible<U>>
        refcnt_ptr(refcnt_ptr<U>&& ptr) noexcept
            : _ptr{ptr._ptr}
        {
            ptr._ptr = nullptr;
        }

        refcnt_ptr& operator=(std::nullptr_t) noexcept(is_nothrow_release)
        {
            release();
            _ptr = nullptr;
            return *this;
        }
        template<typename U, typename = enable_if_compatible<U>>
        refcnt_ptr& operator=(U* ptr) noexcept(is_nothrow_acquire && is_nothrow_release)
        {
            release();
            _ptr = ptr;
            acquire();
            return *this;
        }
        refcnt_ptr& operator=(const refcnt_ptr& ptr) noexcept(is_nothrow_acquire && is_nothrow_release)
        {
            release();
            _ptr = ptr._ptr;
            acquire();
            return *this;
        }
        template<typename U, typename = enable_if_compatible<U>>
        refcnt_ptr& operator=(const refcnt_ptr<U>& ptr) noexcept(is_nothrow_acquire && is_nothrow_release)
        {
            release();
            _ptr = ptr._ptr;
            acquire();
            return *this;
        }
        refcnt_ptr& operator=(refcnt_ptr&& ptr) noexcept(is_nothrow_release)
        {
            release();
            _ptr = ptr._ptr;
            ptr._ptr = nullptr;
            return *this;
        }
        template<typename U, typename = enable_if_compatible<U>>
        refcnt_ptr& operator=(refcnt_ptr<U>&& ptr) noexcept(is_nothrow_release)
        {
            release();
            _ptr = ptr._ptr;
            ptr._ptr = nullptr;
            return *this;
        }

        T* operator->() const noexcept
        {
            return _ptr;
        }
        T& operator*() const noexcept
        {
            return *_ptr;
        }

        T* get() const noexcept
        {
            return _ptr;
        }

        explicit operator bool() const noexcept
        {
            return _ptr != nullptr;
        }
    private:
        void acquire() noexcept(is_nothrow_acquire)
        {
            if(_ptr)
                _ptr->acquire();
        }
        void release() noexcept(is_nothrow_release)
        {
            if(_ptr)
                _ptr->release();
        }
        T* _ptr;
    };

    template<typename T, typename...Args>
    auto make_refcnt(Args&&...args) noexcept(std::is_nothrow_constructible_v<T, Args...>)
    {
        return refcnt_ptr<T>(new T(std::forward<Args>(args)...));
    };

    template<typename T, typename U>
    refcnt_ptr<T> static_pointer_cast(const refcnt_ptr<U>& ptr) noexcept
    {
        return refcnt_ptr<T>(static_cast<T*>(ptr.get()));
    };
    template<typename T, typename U>
    refcnt_ptr<T> dynamic_pointer_cast(const refcnt_ptr<U>& ptr) noexcept
    {
        return refcnt_ptr<T>(dynamic_cast<T*>(ptr.get()));
    };

    template<typename T, typename Cnt = uintptr_t>
    class refcnt_base
    {
    public:
        refcnt_base(const refcnt_base&) = delete;
        refcnt_base(refcnt_base&&) = delete;
        refcnt_base& operator=(const refcnt_base&) = delete;
        refcnt_base& operator=(refcnt_base&&) = delete;

        refcnt_base() noexcept = default;

        template<typename U = T>
        std::enable_if_t<std::is_base_of_v<T, U>, refcnt_ptr<U>>
        refcnt_from_this() noexcept(std::is_nothrow_constructible_v<refcnt_ptr<U>, U*>)
        {
            return refcnt_ptr<U>{static_cast<U*>(this)};
        }
        template<typename U = T>
        std::enable_if_t<std::is_base_of_v<T, U>, refcnt_ptr<const U>>
        refcnt_from_this() const noexcept(std::is_nothrow_constructible_v<refcnt_ptr<const U>, const U*>)
        {
            return refcnt_ptr<const U>{static_cast<const T*>(this)};
        }

        void acquire() const noexcept
        {
            ++_cnt;
        }
        void release() const noexcept(noexcept(std::declval<T>().~T()))
        {
            if(!--_cnt)
                delete static_cast<T *>(const_cast<refcnt_base *>(this));
        }

    private:
        mutable Cnt _cnt{0};
    };
    template<typename T, typename Cnt = uintptr_t>
    using safe_refcnt_base = refcnt_base<T, std::atomic<Cnt>>;
}

#endif