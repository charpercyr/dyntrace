#ifndef DYNTRACE_INJECT_PTRACE_HPP_
#define DYNTRACE_INJECT_PTRACE_HPP_

#include "remote_ptr.hpp"

#include <cstdint>
#include <signal.h>
#include <sys/user.h>

#if defined(__i386__) || defined(__x86_64__)
using user_regs = user_regs_struct;
#elif defined(__powerpc__) || defined(__powerpc64__)
using user_regs = pt_regs;
#endif

namespace dyntrace::inject
{
    class ptrace
    {
    public:

        explicit ptrace(pid_t pid);
        ~ptrace();

        user_regs get_regs() const;
        void set_regs(const user_regs& regs);

        void write(remote_ptr to, const void* from, size_t size);
        void read(void* to, remote_ptr from, size_t size) const;

        siginfo_t get_siginfo() const;

        void cont();
        int wait();

        pid_t pid() const noexcept
        {
            return _pid;
        }

    private:
        pid_t _pid;
    };
}

#endif