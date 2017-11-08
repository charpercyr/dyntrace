#ifndef DYNTRACE_INJECT_REMOTE_HPP_
#define DYNTRACE_INJECT_REMOTE_HPP_

#include "auto_ptr.hpp"
#include "arch/target.hpp"
#include "error.hpp"
#include "remote_util.hpp"
#include "ptrace.hpp"

#include <csignal>
#include <cstring>
#include <vector>
#include <wait.h>

#include <process/process.hpp>

namespace dyntrace::inject
{
    template<typename Target>
    class remote;

    template<typename Target, typename FuncType>
    class remote_function;

    template<typename Target, typename R, typename...Args>
    class remote_function<Target, R(Args...)>
    {
        template<typename Tuple, size_t...Idx>
        void set_args(remote_args<Target>& a, Tuple&& args, std::index_sequence<Idx...>) const
        {
            (_detail::arg<Target>(a,_detail::val_to_reg<Target>(std::get<Idx>(args)), _detail::arg_idx<Idx>{}), ...);
        }
    public:
        remote_function(remote<Target>& remote, remote_ptr<Target> ptr) noexcept
                : _remote{remote}, _ptr{ptr} {}

        R operator()(Args..._args) const;

        remote_ptr<Target> ptr() const noexcept
        {
            return _ptr;
        }

    private:
        remote<Target>& _remote;
        remote_ptr<Target> _ptr;
    };

    template<typename Target>
    class remote
    {
        template<typename, typename>
        friend class remote_function;
    public:
        using regs = typename Target::regs;
        using regval = typename Target::regval;

        explicit remote(ptrace<Target>& pt)
            : _pt{pt}
        {
            auto map = process::memmap::from_pid(_pt.pid());
            auto b = map.binaries().at(get_executable(_pt.pid()));

            auto func_size = Target::remote_call_impl_size();

            for(const auto& z : b.zones())
            {
                if(flag(z.perms, process::permissions::exec) && z.size() >= func_size)
                {
                    _old_func.resize(func_size);
                    _func_ptr = remote_ptr<Target>(z.start),
                    _pt.read(_func_ptr, _old_func.data(), func_size);
                    _pt.write(Target::remote_call_impl_ptr(), _func_ptr, func_size);
                    return;
                }
            }
            throw inject_error("Could not find space to prepare");
        }
        ~remote()
        {
            _pt.write(_old_func.data(), _func_ptr, Target::remote_call_impl_size());
        }

        remote_auto_ptr<Target> malloc(size_t size, remote_ptr<Target> _malloc, remote_ptr<Target> _free)
        {
            auto r_malloc = function<remote_ptr<Target>(size_t)>(_malloc);
            auto r_free = function<void(remote_ptr<Target>)>(_free);
            return remote_auto_ptr<Target>{r_malloc(size), [r_free](remote_ptr<Target> ptr)
            {
                r_free(ptr);
            }};
        }

        remote_auto_ptr<Target> mmap(remote_ptr<Target> addr, size_t size, int prot, int flags, int fd, off_t offset,
                                     remote_ptr<Target> _mmap, remote_ptr<Target> _munmap)
        {
            auto r_mmap = function<remote_ptr<Target>(remote_ptr<Target>, size_t, int, int, int, off_t)>(_mmap);
            auto r_munmap = function<void(remote_ptr<Target>, size_t)>(_munmap);
            return remote_auto_ptr<Target>{r_mmap(addr, size, prot, flags, fd, offset), [r_munmap, size](remote_ptr<Target> ptr)
            {
                r_munmap(ptr, size);
            }};
        }

        template<typename FuncType>
        remote_function<Target, FuncType> function(remote_ptr<Target> ptr) noexcept
        {
            return remote_function<Target, FuncType>{*this, ptr};
        };

    private:

        regval call(remote_ptr<Target> ptr, const remote_args<Target> &args)
        {
            regs call_regs = _pt.get_regs();
            Target::set_args(_pt, call_regs, args, ptr, _func_ptr);

            _pt.set_regs(call_regs);
            _pt.cont();

            waitpid(_pt.pid(), nullptr, 0);
            auto siginfo = _pt.get_siginfo();
            if(siginfo.si_signo != SIGTRAP)
            {
                throw inject_error("Process received signal " + std::to_string(siginfo.si_signo) + " (" + std::string{strsignal(siginfo.si_signo)} + ") while running remote_call");
            }

            call_regs = _pt.get_regs();
            return Target::get_return(call_regs);
        }

        ptrace<Target>& _pt;
        remote_ptr<Target> _func_ptr;
        std::vector<char> _old_func;
    };

    template<typename Target, typename R, typename...Args>
    R remote_function<Target, R(Args...)>::operator()(Args...args) const
    {
        remote_args<Target> a{};
        set_args(a, std::forward_as_tuple(args...), std::index_sequence_for<Args...>{});
        return _detail::reg_to_val<Target, R>(_remote.call(_ptr, a));
    }
}

#endif