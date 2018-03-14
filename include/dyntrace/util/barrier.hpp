#ifndef DYNTRACE_UTIL_BARRIER_HPP_
#define DYNTRACE_UTIL_BARRIER_HPP_

#include <condition_variable>
#include <mutex>

namespace dyntrace
{
    class barrier
    {
    public:
        barrier(const barrier& b) = delete;
        barrier(barrier&&) = delete;
        barrier& operator=(const barrier&) = delete;
        barrier& operator=(barrier&&) = delete;

        explicit barrier(uintptr_t n)
            : _max{n} {}

        bool wait()
        {
            std::unique_lock lock{_lock};
            ++_count;
            _cond.notify_all();
            while(!_cancel && _count < _max)
                _cond.wait(lock);
            return !_cancel;
        }

        void cancel()
        {
            _cancel = true;
            _cond.notify_all();
        }

    private:
        std::mutex _lock;
        std::condition_variable _cond;
        uintptr_t _count{0};
        uintptr_t _max;
        bool _cancel{false};
    };
}

#endif