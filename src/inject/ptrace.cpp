#include "dyntrace/inject/ptrace.hpp"

#include "dyntrace/inject/error.hpp"

#include <boost/log/trivial.hpp>

#include <cstring>
#include <sys/ptrace.h>
#include <wait.h>

using namespace dyntrace::inject;

namespace
{
    long do_ptrace(const std::string& name, int req, pid_t pid, void* addr, void* data)
    {
        long ret;
        if((ret = ::ptrace(__ptrace_request(req), pid, addr, data)) != 0)
        {
            throw inject_error{name + " failed: " + strerror(errno)};
        }
        return ret;
    }
}

ptrace::ptrace(pid_t pid)
    : _pid{pid}
{
    do_ptrace("attach", PTRACE_ATTACH, _pid, nullptr, nullptr);
    wait();
}

ptrace::~ptrace()
{
    try
    {
        do_ptrace("detach", PTRACE_DETACH, _pid, nullptr, nullptr);
    }
    catch(const std::exception& e)
    {
        BOOST_LOG_TRIVIAL(error) << e.what();
    }
    catch(...)
    {
        BOOST_LOG_TRIVIAL(error) << "unknown error";
    }
}

user_regs ptrace::get_regs() const
{
    user_regs res{};
    do_ptrace("get_regs", PTRACE_GETREGS, _pid, nullptr, &res);
    return res;
}

void ptrace::set_regs(const user_regs &regs)
{
    do_ptrace("set_regs", PTRACE_SETREGS, _pid, nullptr, const_cast<user_regs*>(&regs));
}

void ptrace::write(remote_ptr _to, const void *_from, size_t _size)
{
    auto to = _to.as<long*>();
    auto from = (void**)_from;

    size_t size = _size / sizeof(long);
    size_t rem = _size % sizeof(long);
    for(size_t i = 0; i < size; ++i)
    {
        do_ptrace("write", PTRACE_POKEDATA, _pid, to + i, from[i]);
    }

    if(rem)
    {
        void* data;
        read(&data, _to + size, sizeof(long));
        memcpy(&data, from + size, rem);
        do_ptrace("write", PTRACE_POKEDATA, _pid, to + size, data);
    }
}

void ptrace::read(void *_to, remote_ptr _from, size_t _size) const
{
    using namespace std::string_literals;


    size_t size = _size / sizeof(long);
    size_t rem = _size % sizeof(long);

    auto to = reinterpret_cast<long*>(_to);
    auto from = _from.as<long*>();

    errno = 0;
    for(size_t i = 0; i < size; ++i)
    {
        long data = ::ptrace(PTRACE_PEEKDATA, _pid, from + i, nullptr);
        if(!data && errno)
            throw inject_error{"read failed: "s + strerror(errno)};
        to[i] = data;
    }

    if(rem)
    {
        long data = ::ptrace(PTRACE_PEEKDATA, _pid, from + size, nullptr);
        if(!data && errno)
            throw inject_error{"read failed: "s + strerror(errno)};
        memcpy(to + size, &data, rem);
    }
}

siginfo_t ptrace::get_siginfo() const
{
    siginfo_t sig{};
    do_ptrace("get_siginfo", PTRACE_GETSIGINFO, _pid, nullptr, &sig);
    return sig;
}

int ptrace::wait()
{
    using namespace std::string_literals;
    int status;
    if(waitpid(_pid, &status, WUNTRACED) == -1)
        throw inject_error{"wait failed :"s + strerror(errno)};
    return status;
}

void ptrace::cont()
{
    do_ptrace("cont", PTRACE_CONT, _pid, nullptr, nullptr);
}