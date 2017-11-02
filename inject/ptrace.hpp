#ifndef DYNTRACE_INJECT_PTRACE_HPP_
#define DYNTRACE_INJECT_PTRACE_HPP_

#include <memory.h>

#include <sys/ptrace.h>
#include <signal.h>
#include <wait.h>

#include "arch/ptrace.hpp"
#include "error.hpp"
#include "remote_util.hpp"
#include "util/util.hpp"

namespace dyntrace::inject
{

    template<typename Arch, typename FuncType>
    class remote_function;

    template<typename Arch>
    class ptrace
    {
        template<typename, typename>
        friend class remote_function;
    public:
        explicit ptrace(pid_t pid)
            : _pid{pid}, _arch{*this}
        {
            if(::ptrace(PTRACE_ATTACH, _pid, nullptr, nullptr) != 0)
            {
                error("Could not attach to process " + std::to_string(_pid));
            }
            waitpid(_pid, nullptr, 0);
            try
            {
                _regs = get_regs();
            }
            catch(...)
            {
                ::ptrace(PTRACE_DETACH, _pid, nullptr, nullptr);
                throw;
            }
            _arch.prepare();
        }
        ~ptrace() noexcept
        {
            _arch.cleanup();
            ::ptrace(PTRACE_SETREGS, _pid, nullptr, &_regs);
            ::ptrace(PTRACE_DETACH, _pid, nullptr, nullptr);
        }

        typename Arch::regs get_regs() const
        {
            typename Arch::regs regs;
            if(::ptrace(PTRACE_GETREGS, _pid, nullptr, &regs) != 0)
            {
                error("Could not get regs");
            }
            return regs;
        }

        void set_regs(const typename Arch::regs& regs)
        {
            if(::ptrace(PTRACE_SETREGS, _pid, nullptr, &regs) != 0)
            {
                error("Could not set regs");
            }
        }

        siginfo_t get_siginfo() const
        {
            siginfo_t info;
            if(::ptrace(PTRACE_GETSIGINFO, _pid, nullptr, &info) != 0)
            {
                error("Could not get siginfo");
            }
            return info;
        }

        void read(remote_ptr<Arch> from, void* to, size_t size) const
        {
            std::vector<long> data(ceil_div(size, sizeof(long)));
            for(size_t i = 0; i < std::size(data); ++i)
            {
                errno = 0;
                data[i] = ::ptrace(PTRACE_PEEKDATA, _pid, from.template ptr<long>() + i, nullptr);
                if(data[i] == -1)
                {
                    if(errno != 0)
                        error("Could not read data");
                }
            }
            memcpy(to, data.data(), size);
        }

        void write(const void* from, remote_ptr<Arch> to, size_t size)
        {
            std::vector<long> data(ceil_div(size, sizeof(long)), 0);
            memcpy(data.data(), from, size);
            for(size_t i = 0; i < std::size(data); ++i)
            {
                if(::ptrace(PTRACE_POKEDATA, _pid, to.template ptr<long>() + i, data[i]) != 0)
                {
                    error("Could not write data");
                }
            }
        }

        void cont()
        {
            if(::ptrace(PTRACE_CONT, _pid, nullptr, nullptr) != 0)
            {
                error("Could not continue");
            }
        }

        pid_t pid() const noexcept
        {
            return _pid;
        }

    private:

        [[noreturn]]
        void error(const std::string& msg) const
        {
            throw errno_inject_error(msg + " {" + std::to_string(_pid) + "}");
        }

        pid_t _pid;
        typename Arch::regs _regs;
        Arch _arch;
    };

    template<typename Arch, typename R, typename...Args>
    class remote_function<Arch, R(Args...)>
    {
        template<typename Tuple, size_t...Idx>
        void set_args(typename Arch::regs& regs, Tuple&& args, std::index_sequence<Idx...>) const
        {
            (_detail::arg<Arch, Idx>(regs,_detail::val_to_reg<Arch>(std::get<Idx>(args))), ...);
        }
    public:
        remote_function(ptrace<Arch>& pt, remote_ptr<Arch> ptr) noexcept
                : _arch{pt._arch}, _ptr{ptr} {}

        R operator()(Args...args) const
        {
            typename Arch::regs regs{};
            set_args(regs, std::forward_as_tuple(args...), std::index_sequence_for<Args...>{});
            return _detail::reg_to_val<Arch, R>(_arch.remote_call(_ptr, regs));
        }

    private:
        Arch& _arch;
        remote_ptr<Arch> _ptr;
    };

}

#endif