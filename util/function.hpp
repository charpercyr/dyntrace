#ifndef DYNTRACE_UTIL_FUNCTION_HPP_
#define DYNTRACE_UTIL_FUNCTION_HPP_

#include <util/error.hpp>

#include <type_traits>
#include <utility>

namespace dyntrace
{
    DYNTRACE_CREATE_ERROR(function_error);

    template<typename>
    class function;

    template<typename R, typename...Args>
    class function<R(Args...)>
    {
        using this_type = function<R(Args...)>;
        using sbo_type = std::aligned_storage<16>;
        template<typename T>
        static constexpr bool is_not_this = !std::is_same_v<std::decay_t<T>, function>;
    public:
        function(std::nullptr_t = nullptr) noexcept
            : _base{nullptr} {}
        function(const function& f)
            : _base{f._base ? f._base->copy(&_sbo, _is_sbo) : nullptr} {}
        function(function&& f)
            : _base{f._base ? f._base->move(&_sbo, _is_sbo) : nullptr}
        {
            if(f._base)
            {
                delete f._base;
                f._base = nullptr;
            }
        }
        template<typename FuncType, typename = std::enable_if_t<is_not_this<FuncType> && !std::is_null_pointer_v<FuncType>>>
        function(FuncType&& f)
            : _base{nullptr}
        {
            create<std::decay_t<FuncType>>(std::forward<FuncType>(f));
        }

        ~function()
        {
            destroy();
        }

        function& operator=(const function& f)
        {
            destroy();
            _base = f._base ? f._base->copy(&_sbo, _is_sbo) : nullptr;
            return *this;
        }
        function& operator=(function&& f)
        {
            destroy();
            _base = f._base ? f._base->move(&_sbo, _is_sbo) : nullptr;
            return *this;
        }
        template<typename FuncType, typename = std::enable_if_t<is_not_this<FuncType> && !std::is_null_pointer_v<FuncType>>>
        function& operator=(FuncType&& f)
        {
            destroy();
            create<std::decay_t<FuncType>>(std::forward<FuncType>(f));
            return *this;
        }
        function& operator=(std::nullptr_t)
        {
            destroy();
            return *this;
        }

        R operator()(Args...args)
        {
            return _base->call(std::forward<Args>(args)...);
        }
        R operator()(Args...args) const
        {
            return _base->call(std::forward<Args>(args)...);
        }

        explicit operator bool() const noexcept
        {
            return _base != nullptr;
        }

    private:
        template<typename FuncType, typename...Ts>
        void create(Ts...ts)
        {
            if constexpr (sizeof(FuncType) <= sizeof(sbo_type))
            {
                _base = new (&_sbo) data<FuncType>(std::forward<Ts>(ts)...);
                _is_sbo = true;
            }
            else
            {
                _base = new data<FuncType>(std::forward<Ts>(ts)...);
                _is_sbo = false;
            }
        }
        void destroy()
        {
            if(!_base)
                return;

            if(_is_sbo)
                _base->~base();
            else
                delete _base;
            _base = nullptr;
        }
        struct base
        {
            virtual ~base() = default;

            virtual R call(Args...args) = 0;

            virtual base* copy(void* sbo, bool& is_sbo) const = 0;
            virtual base* move(void* sbo, bool& is_sbo) = 0;
        };
        template<typename FuncType>
        struct data : base
        {
            FuncType _func;

            data(const FuncType& f)
                : _func{f} {}
            data(FuncType&& f)
                : _func{std::move(f)} {}

            virtual ~data() = default;

            R call(Args...args) override
            {
                return _func(std::forward<Args>(args)...);
            }
            base* copy(void* sbo, bool& is_sbo) const override
            {
                if constexpr (std::is_copy_constructible_v<FuncType>)
                {
                    if constexpr (sizeof(FuncType) <= sizeof(sbo_type))
                    {
                        is_sbo = true;
                        return new(sbo) data<FuncType>{_func};
                    }
                    else
                    {
                        is_sbo = false;
                        return new data<FuncType>{_func};
                    }
                }
                else
                    throw function_error{"Non copyable function"};
            }
            base* move(void* sbo, bool& is_sbo) override
            {
                if constexpr (std::is_move_constructible_v<FuncType>)
                {
                    if constexpr (sizeof(FuncType) <= sizeof(sbo_type))
                    {
                        is_sbo = true;
                        return new(sbo) data<FuncType>{std::move(_func)};
                    }
                    else
                    {
                        is_sbo = false;
                        return new data<FuncType>{std::move(_func)};
                    }
                }
                else
                    throw function_error{"Non movable function"};
            }
        };
        base* _base;
        std::aligned_storage<16> _sbo;
        bool _is_sbo;
    };
}

#endif