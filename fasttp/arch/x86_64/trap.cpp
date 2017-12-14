#include "trap.hpp"

#include <util/locked.hpp>

#include <unistd.h>
#include <signal.h>
#include <ucontext.h>

#include <map>
#include <sys/ucontext.h>

using namespace dyntrace;
using namespace dyntrace::fasttp;

namespace
{
    locked<std::map<uintptr_t, uintptr_t>> redirects;

    struct sigaction old_handler{};
    void trap_handler(int sig, siginfo_t* info, void* _ctx)
    {
        printf("Trap\n");
        auto ctx = reinterpret_cast<ucontext_t*>(_ctx);
        uintptr_t target = 0;

        // If we call the old handler, red may never unlock
        {
            auto red = redirects.lock();
            auto it = red->find(ctx->uc_mcontext.gregs[REG_RIP] - 1);
            if(it != red->end())
                target = it->second;
        }

        if(target)
        {
            ctx->uc_mcontext.gregs[REG_RIP] = target;
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
}

namespace dyntrace::fasttp
{
    trap_redirect_handle add_trap_redirect(code_ptr at, code_ptr redirect) noexcept
    {
        auto red = redirects.lock();
        if(red->empty())
        {
            install_trap_handler();
        }
        red->insert({at.as_int(), redirect.as_int()});
        return trap_redirect_handle{at};
    }

    void remove_trap_redirect(code_ptr at) noexcept
    {
        auto red = redirects.lock();
        red->erase(at.as_int());
        if(red->empty())
        {
            remove_trap_handler();
        }
    }
}