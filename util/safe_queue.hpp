#ifndef DYNTRACE_UTIL_SAFE_QUEUE_HPP_
#define DYNTRACE_UTIL_SAFE_QUEUE_HPP_

#include <condition_variable>
#include <chrono>
#include <mutex>
#include <queue>

namespace dyntrace
{
    template<typename T>
    class safe_queue
    {
    public:

        void put(const T& t)
        {
            std::unique_lock lock{_lock};
            _queue.push(t);
            _cond.notify_one();
        }

        void put(T&& t)
        {
            std::unique_lock lock{_lock};
            _queue.push(std::move(t));
            _cond.notify_one();
        }

        void pop(T& t)
        {
            std::unique_lock lock{_lock};
            while(_queue.empty())
                _cond.wait(lock);
            do_pop(t);
        }

        template<typename Chrono, typename Duration>
        bool try_pop_until(T& t, const std::chrono::time_point<Chrono, Duration>& end)
        {
            std::unique_lock lock{_lock};
            while(_queue.empty())
            {
                if(_cond.wait_until(lock, end) == std::cv_status::timeout)
                    return false;
            }
            do_pop(t);
            return true;
        };

        size_t size() const
        {
            std::unique_lock lock{_lock};
            return _queue.size();
        }

    private:
        void do_pop(T& t)
        {
            t = std::move(_queue.front());
            _queue.pop();
        }
        std::queue<T> _queue;
        mutable std::mutex _lock;
        mutable std::condition_variable _cond;
    };
}

#endif