#include "ptrace.hpp"

#include <process/memmap.hpp>
#include <inject/ptrace.hpp>

#include <iostream>
#include <bits/types/siginfo_t.h>

extern "C" void do_remote_call(void);
extern const size_t do_remote_call_size;

using namespace dyntrace::inject;

namespace
{
    void print_regs(const x86_64::regs& regs, FILE* filp = stdout)
    {
        fprintf(filp, "rax 0x%llx\n", regs.rax);
        fprintf(filp, "rip 0x%llx\n", regs.rip);
        fprintf(filp, "rdi 0x%llx\n", regs.rdi);
        fprintf(filp, "rsi 0x%llx\n", regs.rsi);
        fprintf(filp, "rdx 0x%llx\n", regs.rdx);
        fprintf(filp, "rcx 0x%llx\n", regs.rcx);
        fprintf(filp, "r8  0x%llx\n", regs.r8);
        fprintf(filp, "r9  0x%llx\n", regs.r9);
    }
}

x86_64::regval x86_64::remote_call(remote_ptr<x86_64> ptr, const args &r)
{
    auto call_regs = _pt.get_regs();

    call_regs.rdi = r._0;
    call_regs.rsi = r._1;
    call_regs.rdx = r._2;
    call_regs.rcx = r._3;
    call_regs.r8 = r._4;
    call_regs.r9 = r._5;
    call_regs.r10 = r._6;
    call_regs.r11 = r._7;

    call_regs.rax = ptr.get();
    call_regs.rip = _func_ptr.get();

    _pt.set_regs(call_regs);
    _pt.cont();

    waitpid(_pt.pid(), nullptr, 0);
    auto siginfo = _pt.get_siginfo();
    if(siginfo.si_signo != SIGTRAP)
    {
        print_regs(_pt.get_regs(), stderr);
        throw inject_error("Process received signal " + std::to_string(siginfo.si_signo) + " (" + std::string{strsignal(siginfo.si_signo)} + ") while running remote_call");
    }

    call_regs = _pt.get_regs();
    return call_regs.rax;
}

void x86_64::prepare()
{
    auto map = process::memmap::from_pid(_pt.pid());
    auto b = map.binaries().at(get_executable(_pt.pid()));

    for(const auto& z : b.zones())
    {
        if(flag(z.perms, process::permissions::exec) && z.size() >= do_remote_call_size)
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
void _detail::arg<x86_64, 0>(x86_64::args& r, x86_64::regval val)
{
    r._0 = val;
};
template<>
void _detail::arg<x86_64, 1>(x86_64::args& r, x86_64::regval val)
{
    r._1 = val;
};
template<>
void _detail::arg<x86_64, 2>(x86_64::args& r, x86_64::regval val)
{
    r._2 = val;
};
template<>
void _detail::arg<x86_64, 3>(x86_64::args& r, x86_64::regval val)
{
    r._3 = val;
};
template<>
void _detail::arg<x86_64, 4>(x86_64::args& r, x86_64::regval val)
{
    r._4 = val;
};
template<>
void _detail::arg<x86_64, 5>(x86_64::args& r, x86_64::regval val)
{
    r._5 = val;
};
template<>
void _detail::arg<x86_64, 6>(x86_64::args& r, x86_64::regval val)
{
    r._6 = val;
};
template<>
void _detail::arg<x86_64, 7>(x86_64::args& r, x86_64::regval val)
{
    r._7 = val;
};