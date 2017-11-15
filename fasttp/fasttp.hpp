#ifndef DYNTRACE_FASTTP_FASTTP_HPP_
#define DYNTRACE_FASTTP_FASTTP_HPP_

#include <functional>

#include <process/process.hpp>
#include <tracer.hpp>

#include "code_allocator.hpp"

namespace dyntrace::fasttp
{

    using handler = std::function<void(void*, const tracer::regs&)>;

    class tracepoint
    {
    public:

        tracepoint(void* at, handler&& h, code_allocator& alloc, bool auto_remove)
                : _at{at}, _alloc{alloc}, _auto_remove{auto_remove}
        {
            do_insert(std::move(h));
        }
        ~tracepoint() noexcept
        {
            if(_auto_remove && _at)
                do_remove();
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

        void do_insert(handler&& h);
        void do_remove();

        void* _at;
        code_allocator& _alloc;
        bool _auto_remove;
    };

    class context
    {
    public:
        explicit context(const process::process& proc)
            : _proc{proc}, _alloc{proc} {}

        tracepoint create(void* at, handler&& h, bool auto_remove = true);
        tracepoint create(const std::string& at, handler&& h, bool auto_remove = true);

        void remove(tracepoint& tp);

    private:
        const process::process& _proc;
        code_allocator _alloc;
    };
}

#endif