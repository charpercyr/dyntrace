#ifndef DYNTRACE_INJECT_PTRACE_HPP_
#define DYNTRACE_INJECT_PTRACE_HPP_

#include <memory.h>

#include <sys/ptrace.h>
#include <signal.h>
#include <wait.h>

#include "error.hpp"
#include "remote_util.hpp"
#include "util/util.hpp"

namespace dyntrace::inject
{

    template<typename Target>
    class ptrace
    {
        template<typename, typename>
        friend class remote_function;
    public:
        explicit ptrace(pid_t pid)
            : _pid{pid}
        {
            if(::ptrace(PTRACE_ATTACH, _pid, nullptr, nullptr) != 0)
            {
                error("Could not attach to process " + std::to_string(_pid));
            }
            waitpid(_pid, nullptr, 0);
            try
            {
                _regs = get_regs();
                _siginfo = get_siginfo();
            }
            catch(...)
            {
                ::ptrace(PTRACE_DETACH, _pid, nullptr, nullptr);
                throw;
            }
        }
        ~ptrace() noexcept
        {
            ::ptrace(PTRACE_SETSIGINFO, _pid, nullptr, &_siginfo);
            ::ptrace(PTRACE_SETREGS, _pid, nullptr, &_regs);
            ::ptrace(PTRACE_DETACH, _pid, nullptr, nullptr);
        }

        typename Target::regs get_regs() const
        {
            typename Target::regs regs;
            if(::ptrace(PTRACE_GETREGS, _pid, nullptr, &regs) != 0)
            {
                error("Could not get regs");
            }
            return regs;
        }

        void set_regs(const typename Target::regs& regs)
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

        void read(remote_ptr<Target> from, void* to, size_t size) const
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

        void write(const void* from, remote_ptr<Target> to, size_t size)
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
        typename Target::regs _regs;
        siginfo_t _siginfo;
    };

}

#endif