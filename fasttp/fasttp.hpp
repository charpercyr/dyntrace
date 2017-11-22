#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include <functional>

#include <process/process.hpp>
#include <tracer.hpp>

#include "code_allocator.hpp"
#include "location.hpp"

namespace dyntrace::fasttp
{

    using handler = std::function<void(void*, const tracer::regs&)>;

    class context;

    class tracepoint
    {
        friend class context;
    public:

        tracepoint(const tracepoint&) = delete;
        tracepoint& operator=(const tracepoint&) = delete;
        tracepoint(tracepoint&& tp) noexcept
            : _at{tp._at}, _alloc{tp._alloc}, _auto_remove{tp._auto_remove}
        {
            tp._at = nullptr;
            tp._auto_remove = false;
        }
        ~tracepoint() noexcept
        {
            if(_auto_remove && _at)
                do_remove();
        }

        tracepoint& operator=(tracepoint&& tp)
        {
            remove();
            _at = tp._at;
            _alloc = tp._alloc;
            _auto_remove = tp._auto_remove;
            tp._at = nullptr;
            tp._auto_remove = false;
            return *this;
        }

        bool auto_remove() const noexcept
        {
            return _auto_remove;
        }

        void auto_remove(bool ar) noexcept
        {
            _auto_remove = ar;
        }

        void remove()
        {
            _auto_remove = false;
            if(_at)
                do_remove();
        }

    private:
        tracepoint(void* at, handler&& h, code_allocator* alloc, bool auto_remove)
                : _at{at}, _alloc{alloc}, _auto_remove{auto_remove}
        {
            do_insert(std::move(h));
        }

        void do_insert(handler&& h);
        void do_remove();

        void* _at;
        code_allocator* _alloc;
        bool _auto_remove;
    };

    class context
    {
    public:
        explicit context(const std::shared_ptr<const process::process>& proc);

        tracepoint create(const location& loc, handler&& h, bool auto_remove = true);

        void remove(tracepoint& tp);

    private:
        std::shared_ptr<const process::process> _proc;
        std::vector<dyntrace::address_range> _basic_blocks;
        code_allocator _alloc;
    };
}

#endif