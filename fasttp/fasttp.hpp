/**
 * Fast tracepoints user classes.
 */
#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include <functional>
#include <optional>
#include <utility>

#include <process/process.hpp>

#include "arch/tracepoint.hpp"
#include "location.hpp"
#include "common.hpp"
#include "util/locked.hpp"
#include "util/flag.hpp"

namespace dyntrace::fasttp
{

    class context;

    /**
     * Handle for a single tracepoint.
     * When this class is destroyed, the tracepoint is removed (unless auto_remove() = false, but you lose the handle).
     */
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

        operator bool() const noexcept
        {
            return _impl != nullptr;
        }

    private:
        arch_tracepoint* _impl;
        context* _ctx;
        bool _auto_remove;
    };

    /**
     * Tracepoint factory class. When this class is destroyed, all tracepoints that were created by this class are destroyed.
     */
    class context
    {
        friend class tracepoint;
    public:

        explicit context(std::shared_ptr<const process::process> proc) noexcept
            : _proc{std::move(proc)}, _impl{*_proc} {}
        ~context();

        /**
         * Creates a tracepoint that will call handler when hit.
         * @param loc Location resolver
         * @param handler Handler to call on hit
         * @param ops Optional options for the tracepoint
         * @return The tracepoint handle. Don't discard or the tracepoint will be immediately deleted (unless auto_remove = false).
         */
        [[nodiscard]] tracepoint create(const location& loc, handler&& handler, options&& ops = {});

    private:

        void remove(void* ptr);

        std::shared_ptr<const process::process> _proc;
        dyntrace::locked<std::map<void*, std::unique_ptr<arch_tracepoint>>> _tracepoints;
        arch_context _impl;
    };
}

#endif