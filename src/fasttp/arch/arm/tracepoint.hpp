#ifndef DYNTRACE_FASSTP_ARCH_ARM_TRACEPOINT_HPP_
#define DYNTRACE_FASSTP_ARCH_ARM_TRACEPOINT_HPP_

#include "context.hpp"

#include "dyntrace/fasttp/common.hpp"
#include "../../code_ptr.hpp"

#include "dyntrace/util/integer_range.hpp"

#include <atomic>

namespace dyntrace::fasttp
{
    class arch_tracepoint;

    struct arch_tracepoint_pad
    {
        uint32_t insn;
        void* handler;
    };

    struct arch_tracepoint_data
    {
        uintptr_t refcount{0};
        std::atomic<arch_tracepoint*> tp{};
        code_ptr handler{};
        size_t handler_size{};
        arch_tracepoint_pad* pad{};
    };

    class arch_tracepoint
    {
    public:
        arch_tracepoint(void* location, handler h, const options& ops);
        ~arch_tracepoint();

        void enable();
        void disable();
        bool enabled() const;

        const void* location() const;

        void call_handler(const arch::regs& r) noexcept;
        void call_entry_handler(const arch::regs& r) noexcept;
        void call_exit_handler(const arch::regs& r) noexcept;

    private:
        arch_tracepoint_data* _data;
        uint32_t _old_code;
        bool _enabled{false};
        code_ptr _location;
        handler _h;
    };
}

#endif