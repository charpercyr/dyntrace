#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include <functional>
#include <optional>
#include <utility>

#include <process/process.hpp>
#include <tracer.hpp>

#include "arch/tracepoint.hpp"
#include "location.hpp"
#include "util/locked.hpp"

namespace dyntrace::fasttp
{

    class context;

    class tracepoint
    {
        friend class context;
    public:
        tracepoint(const tracepoint&) = delete;
        tracepoint& operator=(const tracepoint&) = delete;

        tracepoint(arch_tracepoint* impl, context* ctx, bool auto_remove)
            : _impl{impl}, _ctx{ctx}, _auto_remove{auto_remove} {}
        ~tracepoint();
        tracepoint(tracepoint&& tp) noexcept
            : _impl(tp._impl), _ctx{tp._ctx}, _auto_remove{tp._auto_remove}
        {
            tp._impl = nullptr;
        }

        tracepoint& operator=(tracepoint&& tp) noexcept
        {
            std::swap(_impl, tp._impl);
            std::swap(_ctx, tp._ctx);
            std::swap(_auto_remove, tp._auto_remove);
            return *this;
        }

        void remove();

        bool auto_remove() const noexcept
        {
            return _auto_remove;
        }

        void auto_remove(bool auto_remove) noexcept
        {
            _auto_remove = auto_remove;
        }

    private:
        arch_tracepoint* _impl;
        context* _ctx;
        bool _auto_remove;
    };

    class context
    {
        friend class tracepoint;
    public:
        explicit context(std::shared_ptr<const process::process> proc);
        ~context();

        tracepoint create(const location& loc, handler&& handler, bool auto_remove = true);

        const process::process& process() const noexcept
        {
            return *_proc;
        }

        const std::vector<address_range>& basic_blocks() const noexcept
        {
            return _basic_blocks;
        }

    private:

        void remove(void* ptr);

        std::vector<address_range> _basic_blocks;
        std::shared_ptr<const process::process> _proc;
        dyntrace::locked<std::map<void*, std::unique_ptr<arch_tracepoint>>> _tracepoints;
    };
}

#endif