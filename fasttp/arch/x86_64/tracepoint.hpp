#ifndef DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_TRACEPOINT_HPP_

#include <process/process.hpp>
#include <tracer.hpp>

namespace dyntrace::fasttp
{
    using handler = std::function<void(const void*, const tracer::regs&)>;

    class arch_tracepoint
    {
    public:
        arch_tracepoint(const arch_tracepoint&) = delete;
        arch_tracepoint(arch_tracepoint&& tp) = delete;
        arch_tracepoint& operator=(const arch_tracepoint&) = delete;
        arch_tracepoint& operator=(arch_tracepoint&&) = delete;

        arch_tracepoint(void* location, const process::process& proc, handler&& h)
            : _location{location}, _handler{std::move(h)}
        {
            do_insert(proc);
        }

        ~arch_tracepoint()
        {
            if(_location)
                do_remove();
        }

        void* location() const noexcept
        {
            return _location;
        }

    private:

        void do_insert(const process::process& proc);
        void do_remove();

        void handle(const tracer::regs& r);

        void* _location;
        handler _handler;
        volatile uint64_t _refcount{0};
        uint64_t _old_code;
    };
}

#endif