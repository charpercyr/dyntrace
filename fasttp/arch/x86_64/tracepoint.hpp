#ifndef DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_

#include <arch/arch.hpp>
#include <process/process.hpp>

#include <fasttp/code_ptr.hpp>
#include <fasttp/common.hpp>

#include "context.hpp"

#include <vector>

namespace dyntrace::fasttp
{
    /**
     * x86_64 tracepoint implementation.
     */
    class arch_tracepoint
    {
    public:
        arch_tracepoint(const arch_tracepoint&) = delete;
        arch_tracepoint(arch_tracepoint&& tp) = delete;
        arch_tracepoint& operator=(const arch_tracepoint&) = delete;
        arch_tracepoint& operator=(arch_tracepoint&&) = delete;

        arch_tracepoint(void* location, arch_context& ctx, handler&& h, const options& ops)
            : _location{location}, _user_handler{std::move(h)}
        {
            do_insert(ctx, ops);
        }

        ~arch_tracepoint()
        {
            if(_location)
                do_remove();
        }

        void* location() const noexcept
        {
            return _location.as_ptr();
        }

    private:

        void do_insert(arch_context& ctx, const options& ops);
        void do_remove();

        static void do_handle(const arch_tracepoint *self, const arch::regs &r) noexcept;

        handler _user_handler;
        code_ptr _location;
        code_ptr _handler_location;
        size_t _handler_size{0};
        uint64_t _old_code{0};
        volatile uint64_t _refcount{0};
        std::vector<redirect_handle> _redirects;
    };
}

#endif