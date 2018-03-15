#include "context.hpp"

#include "../../context.hpp"

#include "dyntrace/util/locked.hpp"

#include <signal.h>
#include <sys/ucontext.h>

#include "tracepoint.hpp"

using namespace dyntrace;
using namespace dyntrace::fasttp;

#ifdef __i386__
#define REG(name) REG_E##name
#else // __i386__
#define REG(name) REG_R##name
#endif // __i386__

namespace
{
    shared_locked<std::unordered_map<code_ptr, std::tuple<point_handler, code_ptr>, code_ptr::hash>> redirects;

    arch::regs make_regs(const greg_t* r)
    {
        return arch::regs {
            .ax = static_cast<uintptr_t>(r[REG(AX)]),
            .di = static_cast<uintptr_t>(r[REG(DI)]),
            .si = static_cast<uintptr_t>(r[REG(SI)]),
            .dx = static_cast<uintptr_t>(r[REG(DX)]),
            .cx = static_cast<uintptr_t>(r[REG(CX)]),
#ifdef __x86_64__
            .r8 = static_cast<uintptr_t>(r[REG_R8]),
            .r9 = static_cast<uintptr_t>(r[REG_R9]),
#endif
            .bx = static_cast<uintptr_t>(r[REG(BX)]),
#ifdef __i386__
            .flags = static_cast<uintptr_t>(r[REG_EFL]),
            .sp = static_cast<uintptr_t>(r[REG_ESP]),
            ._res = 0,
            .bp = static_cast<uintptr_t>(REG_EBP),
#else
            .r10 = static_cast<uintptr_t>(r[REG_R10]),
            .r11 = static_cast<uintptr_t>(r[REG_R11]),
            .r12 = static_cast<uintptr_t>(r[REG_R12]),
            .r13 = static_cast<uintptr_t>(r[REG_R13]),
            .r14 = static_cast<uintptr_t>(r[REG_R14]),
            .r15 = static_cast<uintptr_t>(r[REG_R15]),
            .bp = static_cast<uintptr_t>(r[REG_RBP]),
            .flags = static_cast<uintptr_t>(r[REG_EFL]),
            .sp = static_cast<uintptr_t>(r[REG_RSP]),
#endif // __i386__
        };
    }

    struct sigaction old_handler{};
    void trap_handler(int sig, siginfo_t* info, void* _ctx) noexcept
    {
        auto ctx = reinterpret_cast<ucontext_t*>(_ctx);
        code_ptr target{};
        code_ptr from{ctx->uc_mcontext.gregs[REG(IP)] - 1}; // We are one byte too far (after the trap)

        // If we call the old handler, red may never unlock
        {
            auto red = redirects.lock_shared();
            auto it = red->find(from);
            if(it != red->end())
            {
                const auto& h = std::get<point_handler>(it->second);
                if(h)
                    h(from.as_ptr(), make_regs(ctx->uc_mcontext.gregs));
                target = std::get<code_ptr>(it->second);
            }
        }

        if(target)
        {
            ctx->uc_mcontext.gregs[REG(IP)] = target.as<greg_t>();
        }
        else
        {
            if(old_handler.sa_handler || old_handler.sa_sigaction)
            {
                if(old_handler.sa_flags & SA_SIGINFO)
                    old_handler.sa_sigaction(sig, info, _ctx);
                else
                    old_handler.sa_handler(sig);
            }
            else
            {
                // Default behavior
                exit(128 + sig);
            }
        }
    }

    void install_trap_handler()
    {
        struct sigaction act{};
        act.sa_flags = SA_SIGINFO;
        act.sa_sigaction = trap_handler;
        sigaction(SIGTRAP, &act, &old_handler);
    }

    void remove_trap_handler()
    {
        sigaction(SIGTRAP, &old_handler, nullptr);
    }

    void do_add_redirect(point_handler&& h, code_ptr at, code_ptr redirect) noexcept
    {
        auto red = redirects.lock();
        if(red->empty())
        {
            install_trap_handler();
        }
        red->insert_or_assign(at, std::make_tuple(std::move(h), redirect));
    }

    void do_remove_redirect(code_ptr at) noexcept
    {
        auto red = redirects.lock();
        red->erase(at);
        if(red->empty())
        {
            remove_trap_handler();
        }
    }

    template<typename Container>
    void do_remove_redirects(const Container& ats)
    {
        auto red = redirects.lock();
        for(const auto& at : ats)
            red->erase(at);
        if(red->empty())
        {
            remove_trap_handler();
        }
    }
}

void redirect_handle::remove()
{
    if(_at)
    {
        context::instance().arch().remove_redirect(_at);
        _at = {};
    }
}

arch_context::arch_context(context* ctx) noexcept
{
    reclaimer::instance().add_invalid(
        {
            reinterpret_cast<uintptr_t>(__tracepoint_handler),
            reinterpret_cast<uintptr_t>(__tracepoint_handler) + __tracepoint_handler_size,
        }
    );
    reclaimer::instance().add_invalid(
        {
            reinterpret_cast<uintptr_t>(__tracepoint_return_enter_handler),
            reinterpret_cast<uintptr_t>(__tracepoint_return_enter_handler) + __tracepoint_return_enter_handler_size,
        }
    );
    reclaimer::instance().add_invalid(
        {
            reinterpret_cast<uintptr_t>(__tracepoint_return_exit_handler),
            reinterpret_cast<uintptr_t>(__tracepoint_return_exit_handler) + __tracepoint_return_exit_handler_size,
        }
    );
}

arch_context::~arch_context()
{
    do_remove_redirects(_redirects);
}

redirect_handle arch_context::add_redirect(point_handler h, code_ptr at, code_ptr redirect)
{
    do_add_redirect(std::move(h), at, redirect);
    _redirects.insert(at);
    return redirect_handle{at};
}

void arch_context::remove_redirect(code_ptr at)
{
    auto it = _redirects.find(at);
    if(it != _redirects.end())
    {
        _redirects.erase(it);
        do_remove_redirect(at);
    }
}