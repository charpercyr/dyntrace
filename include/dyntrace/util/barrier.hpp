#ifndef DYNTRACE_UTIL_BARRIER_HPP_
#define DYNTRACE_UTIL_BARRIER_HPP_

#include <atomic>
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
            : _count{n}, _max{n} {}

        bool wait()
        {
            std::unique_lock lock{_lock};
            auto gen = _gen;

            if(--_count == 0)
            {
                _gen = !_gen;
                _count = _max;
                lock.unlock();
                _cond.notify_all();
                return !_cancel;
            }

            while(!_cancel && gen == _gen)
                _cond.wait(lock);
            return !_cancel;
        }

        void cancel()
        {
            _cancel = true;
            _cond.notify_all();
        }

    private:
        uintptr_t _count;
        uintptr_t _max;
        std::mutex _lock;
        std::condition_variable _cond;
        bool _gen{false};
        bool _cancel{false};
    };
}

#endif