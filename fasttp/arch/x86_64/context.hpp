/**
 * Global tracepoint data for x86_64.
 */
#ifndef DYNTRACE_FASTTP_ARCH_X86_64_CONTEXT_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_CONTEXT_HPP_

#include <memory>
#include <unordered_set>
#include <vector>

#include <arch/arch.hpp>
#include <fasttp/code_ptr.hpp>
#include <fasttp/common.hpp>
#include <process/process.hpp>
#include <util/integer_range.hpp>

namespace dyntrace::fasttp
{

    class arch_context;

    /**
     * Handle that represents a trap redirection.
     * When this class is destroyed, the redirection is removed from the active list.
     * When a trap is hit, it checks for the active redirections.
     * If found, it calls a handler and then sets rip to the redirection. Else it calls the old handler.
     * **DOES NOT WORK WITH GDB**. GDB ignores the fact that a trap handler could be set by the debugged program.
     */
    class redirect_handle
    {
    public:
        redirect_handle(const redirect_handle&) = delete;
        redirect_handle& operator=(const redirect_handle&) = delete;

        redirect_handle(arch_context* ctx, code_ptr at) noexcept
            : _ctx{ctx}, _at{at} {}

        redirect_handle(redirect_handle&& h) noexcept
            : _ctx{h._ctx}, _at{h._at}
        {
            h._at = {};
        }

        redirect_handle& operator=(redirect_handle&& h) noexcept
        {
            remove();
            _ctx = h._ctx;
            _at = h._at;
            h._at = {};
            return *this;
        }

        ~redirect_handle()
        {
            remove();
        }

        void remove();

    private:
        arch_context* _ctx;
        code_ptr _at;
    };

    /**
     * Global data for tracepoints.
     */
    class arch_context
    {
        friend class redirect_handle;
    public:
        arch_context(const process::process& proc);
        ~arch_context();

        const process::process& process() const noexcept
        {
            return _proc;
        }

        const std::optional<std::vector<address_range>>& basic_blocks() const noexcept
        {
            return _basic_blocks;
        }

        redirect_handle add_redirect(code_ptr at, code_ptr redirect, handler&& h = nullptr);

    private:

        void remove_redirect(code_ptr at);

        const process::process& _proc;
        std::optional<std::vector<address_range>> _basic_blocks;
        std::unordered_set<code_ptr, code_ptr::hash> _redirects;
    };
}

#endif