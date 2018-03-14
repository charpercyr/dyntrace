#ifndef DYNTRACE_UTIL_SEMAPHORE_HPP_
#define DYNTRACE_UTIL_SEMAPHORE_HPP_

#include <condition_variable>
#include <mutex>

namespace dyntrace
{
    class semaphore
    {
    public:
        explicit semaphore(uintptr_t count)
            : _count{count} {}

        void put()
        {
            std::unique_lock lock{_lock};
            ++_count;
            _cond.notify_one();
        }

        void wait()
        {
            std::unique_lock lock{_lock};
            while(!_count)
                _cond.wait(lock);
            --_count;
        }

        template<typename C, typename D>
        bool wait_until(std::chrono::time_point<C, D> t)
        {
            std::unique_lock lock{_lock};
            while(!_count)
            {
                if(_cond.wait_until(lock, t) == std::cv_status::timeout)
                    return false;
            }
            --_count;
            return true;
        }

    private:
        std::mutex _lock;
        std::condition_variable _cond;
        uintptr_t _count;
    };
}

#endif