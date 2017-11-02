#include "ptrace.hpp"

#include <process/memmap.hpp>
#include <inject/ptrace.hpp>

extern "C" void do_remote_call(void);
extern const size_t do_remote_call_size;

using namespace dyntrace::inject;

x86_64::regval x86_64::remote_call(remote_ptr<x86_64> ptr, const regs &r)
{
    auto old_regs = _pt.get_regs();
    auto call_regs = old_regs;

    call_regs.rdi = r.rdi;
    call_regs.rsi = r.rsi;
    call_regs.rdx = r.rdx;
    call_regs.rcx = r.rcx;
    call_regs.r8 = r.r8;
    call_regs.r9 = r.r9;

    call_regs.rax = ptr.get();
    call_regs.rip = _func_ptr.get();

    _pt.set_regs(call_regs);
    _pt.cont();

    waitpid(_pt.pid(), nullptr, 0);
    auto siginfo = _pt.get_siginfo();
    if(siginfo.si_signo != SIGTRAP)
    {
        throw inject_error("Process crashed while running remote_call");
    }

    call_regs = _pt.get_regs();
    return call_regs.rax;
}

void x86_64::prepare()
{
    auto map = process::memmap::from_pid(_pt.pid());
    auto b = map.find(get_executable(_pt.pid()));

    for(const auto& z : b.zones())
    {
        if(flag(z.perms, process::perms::exec) && z.size() >= do_remote_call_size)
        {
            _old_func.resize(do_remote_call_size);
            _func_ptr = remote_ptr<x86_64>{z.start};
            _pt.read(_func_ptr, _old_func.data(), do_remote_call_size);
            _pt.write(reinterpret_cast<const void*>(do_remote_call), _func_ptr, do_remote_call_size);
            return;
        }
    }
    throw inject_error("Could not find place to prepare x86_64");
}

void x86_64::cleanup()
{
    _pt.write(_old_func.data(), _func_ptr, do_remote_call_size);
}

template<>
void _detail::arg<x86_64, 0>(x86_64::regs& r, x86_64::regval val)
{
    r.rdi = val;
};
template<>
void _detail::arg<x86_64, 1>(x86_64::regs& r, x86_64::regval val)
{
    r.rsi = val;
};
template<>
void _detail::arg<x86_64, 2>(x86_64::regs& r, x86_64::regval val)
{
    r.rdx = val;
};
template<>
void _detail::arg<x86_64, 3>(x86_64::regs& r, x86_64::regval val)
{
    r.rcx = val;
};
template<>
void _detail::arg<x86_64, 4>(x86_64::regs& r, x86_64::regval val)
{
    r.r8 = val;
};
template<>
void _detail::arg<x86_64, 5>(x86_64::regs& r, x86_64::regval val)
{
    r.r9 = val;
};