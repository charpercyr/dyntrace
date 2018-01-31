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
    /**
     * x86_64 tracepoint implementation.
     */
    class arch_tracepoint : public std::enable_shared_from_this<arch_tracepoint>
    {
    public:
        arch_tracepoint(const arch_tracepoint&) = delete;
        arch_tracepoint(arch_tracepoint&& tp) = delete;
        arch_tracepoint& operator=(const arch_tracepoint&) = delete;
        arch_tracepoint& operator=(arch_tracepoint&&) = delete;

        arch_tracepoint(void* location, handler&& h, const options& ops);
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
            return _refcount;
        }

        address_range range() const noexcept
        {
            return {_handler_location.as_int(), _handler_location.as_int() + _handler_size};
        }

        void call_handler(const arch::regs& r) noexcept;
        void call_trap_handler(const void* where, const arch::regs& r) noexcept;

    private:
        void do_remove();

        std::atomic_uint64_t _refcount{0}; // Has to be first, assembly increases this value.
        handler _user_handler;
        handler _trap_handler;
        code_ptr _location;
        code_ptr _handler_location;
        size_t _handler_size{0};
        uint64_t _old_code{0};
        std::vector<redirect_handle> _redirects;
        bool _enabled{false};
    };
}

#endif