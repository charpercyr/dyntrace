#include "context.hpp"

#include "dyntrace/fasttp/context.hpp"

#include "dyntrace/util/locked.hpp"

#include <signal.h>
#include <sys/ucontext.h>

#include "tracepoint.hpp"

using namespace dyntrace;
using namespace dyntrace::fasttp;

namespace
{
    shared_locked<std::unordered_map<code_ptr, std::tuple<handler, code_ptr>, code_ptr::hash>> redirects;

    arch::regs make_regs(const greg_t* r)
    {
        return arch::regs {
            .rax = static_cast<uintptr_t>(r[REG_RAX]),
            .rdi = static_cast<uintptr_t>(r[REG_RDI]),
            .rsi = static_cast<uintptr_t>(r[REG_RSI]),
            .rdx = static_cast<uintptr_t>(r[REG_RDX]),
            .rcx = static_cast<uintptr_t>(r[REG_RCX]),
            .r8 = static_cast<uintptr_t>(r[REG_R8]),
            .r9 = static_cast<uintptr_t>(r[REG_R9]),
            .rbx = static_cast<uintptr_t>(r[REG_RBX]),
            .r10 = static_cast<uintptr_t>(r[REG_R10]),
            .r11 = static_cast<uintptr_t>(r[REG_R11]),
            .r12 = static_cast<uintptr_t>(r[REG_R12]),
            .r13 = static_cast<uintptr_t>(r[REG_R13]),
            .r14 = static_cast<uintptr_t>(r[REG_R14]),
            .r15 = static_cast<uintptr_t>(r[REG_R15]),
            .rbp = static_cast<uintptr_t>(r[REG_RBP]),
            .rflags = static_cast<uintptr_t>(r[REG_EFL]),
            .rsp = static_cast<uintptr_t>(r[REG_RSP]),
        };
    }

    struct sigaction old_handler{};
    void trap_handler(int sig, siginfo_t* info, void* _ctx) noexcept
    {
        auto ctx = reinterpret_cast<ucontext_t*>(_ctx);
        code_ptr target{};
        code_ptr from{ctx->uc_mcontext.gregs[REG_RIP] - 1}; // We are one byte too far (after the trap)

        // If we call the old handler, red may never unlock
        {
            auto red = redirects.lock_shared();
            auto it = red->find(from);
            if(it != red->end())
            {
                const auto& h = std::get<handler>(it->second);
                if(h)
                    h(from.as_ptr(), make_regs(ctx->uc_mcontext.gregs));
                target = std::get<code_ptr>(it->second);
            }
        }

        if(target)
        {
            ctx->uc_mcontext.gregs[REG_RIP] = target.as<greg_t>();
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

    void do_add_redirect(handler&& h, code_ptr at, code_ptr redirect) noexcept
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
    ctx->get_reclaimer().add_invalid(
        {
            reinterpret_cast<uintptr_t>(__tracepoint_handler),
            reinterpret_cast<uintptr_t>(__tracepoint_handler) + __tracepoint_handler_size,
        }
    );
}

arch_context::~arch_context()
{
    do_remove_redirects(_redirects);
}

redirect_handle arch_context::add_redirect(handler h, code_ptr at, code_ptr redirect)
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