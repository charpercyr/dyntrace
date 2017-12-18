#ifndef DYNTRACE_FASTTP_ARCH_X86_64_CONTEXT_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_CONTEXT_HPP_

#include <memory>
#include <unordered_set>
#include <vector>

#include <arch/arch.hpp>
#include <fasttp/code_ptr.hpp>
#include <process/process.hpp>
#include <util/integer_range.hpp>

namespace dyntrace::fasttp
{
    using handler = std::function<void(const void*, const arch::regs&)>;

    class arch_context;

    class redirect_handle
    {
    public:
        redirect_handle(const redirect_handle&) = delete;
        redirect_handle& operator=(const redirect_handle&) = delete;

        redirect_handle(arch_context* ctx, code_ptr at)
            : _ctx{ctx}, _at{at} {}

        redirect_handle(redirect_handle&& h) noexcept
            : _ctx{h._ctx}, _at{h._at}
        {
            h._at = nullptr;
        }

        redirect_handle& operator=(redirect_handle&& h) noexcept
        {
            remove();
            _ctx = h._ctx;
            _at = h._at;
            h._at = nullptr;
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