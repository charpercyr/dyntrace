#ifndef DYNTRACE_INJECT_EXECUTOR_HPP_
#define DYNTRACE_INJECT_EXECUTOR_HPP_

#include "common.hpp"
#include "error.hpp"
#include "ptrace.hpp"

#include "dyntrace/process/process.hpp"

#include <memory>
#include <regex>
#include <string>

namespace dyntrace::inject
{
    namespace _detail
    {
        template<typename Int>
        std::enable_if_t<
            std::is_integral_v<Int> &&
                sizeof(Int) <= sizeof(uintptr_t),
            uintptr_t> to_int(Int i)
        {
            return static_cast<Int>(i);
        }

        inline uintptr_t to_int(remote_ptr p)
        {
            return p.as_int();
        }

        inline uintptr_t to_int(unique_remote_ptr p)
        {
            return p.as_int();
        }

        template<typename Int>
        std::enable_if_t<
            std::is_integral_v<Int> &&
            sizeof(Int) <= sizeof(uintptr_t),
            Int> from_int(uintptr_t i)
        {
            return static_cast<Int>(i);
        }

        template<typename RPtr>
        std::enable_if_t<std::is_same_v<RPtr, remote_ptr>, remote_ptr> from_int(uintptr_t i)
        {
            return remote_ptr{i};
        }

        template<typename Void>
        std::enable_if_t<std::is_void_v<Void>> from_int(uintptr_t)
        {

        }
    }

    class arch_executor;
    template<typename Func>
    class remote_function;

    class executor
    {
        template<typename>
        friend class remote_function;
    public:

        explicit executor(pid_t pid)
            : executor{std::make_shared<const process::process>(pid)} {}
        explicit executor(process_ptr proc);
        ~executor();

        template<typename Func>
        remote_function<Func> create(const std::string& name)
        {
            return remote_function<Func>{find(name), this};
        }
        template<typename Func>
        remote_function<Func> create(const std::string& name, const std::regex& lib)
        {
            return remote_function<Func>{find(name, lib), this};
        }

        remote_ptr find(const std::string& name)
        {
            auto sym = _proc->get(name);
            return remote_ptr{sym.value};
        }
        remote_ptr find(const std::string& name, const std::regex& lib)
        {
            auto sym = _proc->get(name, lib);
            return remote_ptr{sym.value};
        }

        void copy(remote_ptr to, const void* from, size_t size);
        void copy(void* to, remote_ptr from, size_t size);

        process_ptr get_process() const noexcept
        {
            return _proc;
        }

    private:
        uintptr_t remote_call(remote_ptr func, const remote_args& args);

        std::unique_ptr<arch_executor> _impl;
        process_ptr _proc;
    };

    template<typename R, typename...Args>
    class remote_function<R(Args...)>
    {
        static_assert(sizeof...(Args) <= max_remote_args, "Too many arguments");
    public:
        using result_type = R;

        remote_function()
            : _func{nullptr}, _e{nullptr} {}

        explicit remote_function(remote_ptr func, executor* e)
            : _func{func}, _e{e} {}

        R operator()(Args...args) const
        {
            if(!_func)
                throw inject_error{"bad remote function call"};
            return call(std::forward_as_tuple(args...), std::index_sequence_for<Args...>{});
        }

    private:
        template<typename Tuple, size_t...Idx>
        R call(Tuple&& args, std::index_sequence<Idx...>) const
        {
            return _detail::from_int<R>(
                _e->remote_call(
                    _func,
                    {_detail::to_int(std::get<Idx>(args))...}
                )
            );
        }

        remote_ptr _func;
        executor* _e;
    };

    using remote_malloc = std::function<unique_remote_ptr(size_t)>;

    remote_malloc make_malloc(executor& e);
}

#endif