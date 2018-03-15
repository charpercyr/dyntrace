#ifndef DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_

#include "context.hpp"

#include "code_ptr.hpp"
#include "dyntrace/fasttp/common.hpp"

#include "dyntrace/arch/arch.hpp"
#include "dyntrace/process/process.hpp"

#include <atomic>
#include <vector>

namespace dyntrace::fasttp
{
    class arch_tracepoint;

    /**
     * tracepoint data that will be delay-deleted (using the reclaimer)
     */
    struct arch_tracepoint_code
    {
        std::atomic<uintptr_t> refcount; // Has to be first
        code_ptr handler;
        size_t handler_size;
        std::atomic<arch_tracepoint*> tracepoint;
    };

    /**
     * x86 tracepoint implementation.
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

        const void* location() const noexcept
        {
            return _location.as_ptr();
        }

        address_range range() const noexcept
        {
            return address_range{_code->handler.as_int(), _code->handler.as_int() + _code->handler_size};
        }

        void call_handler(const arch::regs& r) noexcept;
        void call_enter_handler(const arch::regs& r) noexcept;
        void call_exit_handler(const arch::regs& r) noexcept;

    private:

        arch_tracepoint_code* _code;
        handler _user_handler;
        point_handler _trap_handler;
        code_ptr _location;
        uint64_t _old_code{0};
        size_t _ool_size;
        std::vector<redirect_handle> _redirects;
        bool _enabled{false};
    };
}

#endif