#ifndef DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_

#include <arch/arch.hpp>
#include <process/process.hpp>

#include <fasttp/code_ptr.hpp>
#include <fasttp/common.hpp>

#include "context.hpp"

#include <atomic>
#include <vector>

namespace dyntrace::fasttp
{
    class arch_tracepoint;

    struct arch_tracepoint_code
    {
        std::atomic_uint64_t refcount; // Has to be first
        code_ptr handler;
        size_t handler_size;
        std::atomic<arch_tracepoint*> tracepoint;
    };

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

        arch_tracepoint(void* location, handler h, const options& ops);

        ~arch_tracepoint();

        void enable() noexcept;
        void disable() noexcept;

        bool enabled() const noexcept
        {
            return _enabled;
        }

        void* location() const noexcept
        {
            return _location.as_ptr();
        }

        uintptr_t refcount() const noexcept
        {
            return _code->refcount.load(std::memory_order_relaxed);
        }

        address_range range() const noexcept
        {
            return address_range{_code->handler.as_int(), _code->handler.as_int() + _code->handler_size};
        }

        void call_handler(const arch::regs& r) noexcept;

    private:

        owner<arch_tracepoint_code*> _code;
        handler _user_handler;
        handler _trap_handler;
        code_ptr _location;
        uint64_t _old_code{0};
        std::vector<redirect_handle> _redirects;
        bool _enabled{false};
    };
}

#endif