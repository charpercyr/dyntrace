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
    class arch_tracepoint;
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

        arch_tracepoint(void* location, context* ctx, handler&& h, const options& ops)
            : _location{location}, _user_handler{std::move(h)}, _ctx{ctx}
        {
            do_insert(ops);
        }

        ~arch_tracepoint()
        {
            if(_location)
                do_remove();
        }

        void enable() noexcept;
        void disable() noexcept;

        void* location() const noexcept
        {
            return _location.as_ptr();
        }

        uintptr_t refcount() const noexcept
        {
            return _refcount;
        }

        address_range range() const noexcept
        {
            return {_handler_location.as_int(), _handler_location.as_int() + _handler_size};
        }

        void call_handler(const arch::regs& r) noexcept;

    private:

        void do_insert(const options& ops);
        void do_remove();

        volatile uintptr_t _refcount{0}; // Has to be first, assembly increases this value.
        handler _user_handler;
        code_ptr _location;
        code_ptr _handler_location;
        size_t _handler_size{0};
        uint64_t _old_code{0};
        std::vector<redirect_handle> _redirects;
        context* _ctx;
        bool _enabled{false};
    };
}

#endif