#ifndef DYNTRACE_FASTTP_RECLAIMER_HPP_
#define DYNTRACE_FASTTP_RECLAIMER_HPP_

#include <functional>
#include <future>
#include <list>
#include <set>
#include <thread>
#include <variant>
#include <vector>

#include <process/process.hpp>
#include <util/barrier.hpp>
#include <util/integer_range.hpp>
#include <util/locked.hpp>
#include <util/safe_queue.hpp>

#include <signal.h>

namespace dyntrace::fasttp
{
    class reclaimer
    {
    public:
        reclaimer();
        ~reclaimer();

        void reclaim(std::function<bool(uintptr_t)> pred, std::function<void()> del)
        {
            _queue.put(reclaim_work{std::move(pred), std::move(del)});
        }

        void add_invalid(dyntrace::address_range range) noexcept
        {
            auto inv = _always_invalid.lock();
            inv->push_back(range);
        }

        std::future<void> trigger_reclaim() noexcept;

    private:
        struct reclaim_stop {};
        struct reclaim_work
        {
            std::function<bool(uintptr_t)> predicate;
            std::function<void()> deleter;
        };
        struct reclaim_force
        {
            std::function<void()> done;
        };
        using queue_element = std::variant<std::monostate, reclaim_stop, reclaim_work, reclaim_force>;

        struct reclaim_data
        {
            reclaimer* self;
            dyntrace::locked<std::list<std::function<void()>>> to_delete;
            dyntrace::barrier barrier;
            std::atomic<bool> cancel;
        };

        void run();
        void reclaim_batch();

        static void on_usr1(int, siginfo_t* sig, void* ctx);
        static reclaim_data* _reclaim_data;
        static std::mutex _reclaim_lock;

        dyntrace::safe_queue<queue_element> _queue;
        std::list<reclaim_work> _batch;
        dyntrace::locked<std::vector<dyntrace::address_range>> _always_invalid;
        std::thread _thread;
    };
}

#endif