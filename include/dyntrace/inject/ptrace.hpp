#ifndef DYNTRACE_INJECT_PTRACE_HPP_
#define DYNTRACE_INJECT_PTRACE_HPP_

#include <memory>
#include <signal.h>
#include <sys/user.h>

namespace dyntrace::inject
{
    class ptrace
    {
    public:

        explicit ptrace(pid_t pid);
        ~ptrace();

        user_regs_struct get_regs() const;
        void set_regs(const user_regs_struct& regs);

        void write(uintptr_t to, const void* from, size_t size);
        void read(void* to, uintptr_t from, size_t size) const;

        siginfo_t get_siginfo() const;

        void cont();
        int wait();

        pid_t pid();

    private:
        pid_t _pid;
    };
}

#endif