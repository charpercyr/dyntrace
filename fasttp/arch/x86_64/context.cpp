#include "context.hpp"

#include <fasttp/context.hpp>

#include <util/locked.hpp>

#include <signal.h>
#include <sys/ucontext.h>

using namespace dyntrace;
using namespace dyntrace::fasttp;

namespace
{
    locked<std::unordered_map<code_ptr, std::tuple<code_ptr, handler>, code_ptr::hash>> redirects;

    arch::regs make_regs(greg_t* r)
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
            .rflags = static_cast<uintptr_t>(r[REG_EFL]),
            .rbp = static_cast<uintptr_t>(r[REG_RBP]),
            .rsp = static_cast<uintptr_t>(r[REG_RSP]),
        };
    }

    struct sigaction old_handler{};
    void trap_handler(int sig, siginfo_t* info, void* _ctx) noexcept
    {
        auto ctx = reinterpret_cast<ucontext_t*>(_ctx);
        uintptr_t target = 0;
        code_ptr from{ctx->uc_mcontext.gregs[REG_RIP] - 1}; // We are one byte too far (after the trap)

        // If we call the old handler, red may never unlock
        {
            auto red = redirects.lock();
            auto it = red->find(from);
            if(it != red->end())
            {
                target = std::get<code_ptr>(it->second).as_int();
                if(std::get<handler>(it->second))
                {
                    std::get<handler>(it->second)(from.as_ptr(), make_regs(ctx->uc_mcontext.gregs));
                }
            }
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

    void do_add_redirect(code_ptr at, code_ptr redirect, handler&& h) noexcept
    {
        auto red = redirects.lock();
        if(red->empty())
        {
            install_trap_handler();
        }
        red->insert({at, {redirect, std::move(h)}});
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
        _ctx->remove_redirect(_at);
        _at = {};
    }
}

arch_context::arch_context(context* ctx)
    : _allocator{&ctx->process()}
{
    try
    {
        auto dw = ctx->process().dwarf();
        for (const auto &cu : dw.compilation_units())
        {
            for (const auto &sp : cu.root())
            {
                if (sp.tag == dwarf::DW_TAG::subprogram)
                {
                    for (const auto &bb : sp)
                    {
                        // Custom tag for basic block
                        if (static_cast<int>(bb.tag) == 0x1001)
                        {
                            if (!_basic_blocks)
                                _basic_blocks = std::vector<address_range>();
                            auto base = bb[dwarf::DW_AT::low_pc].as_address();
                            auto size = bb[dwarf::DW_AT::high_pc].as_uconstant();
                            _basic_blocks->push_back({base, base + size});
                        }
                    }
                }
            }
        }
    }
    catch (const std::exception &e)
    {
        // No basic block info
    }
}

arch_context::~arch_context()
{
    do_remove_redirects(_redirects);
}

redirect_handle arch_context::add_redirect(code_ptr at, code_ptr redirect, handler&& h)
{
    do_add_redirect(at, redirect, std::move(h));
    _redirects.insert(at);
    return redirect_handle{this, at};
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