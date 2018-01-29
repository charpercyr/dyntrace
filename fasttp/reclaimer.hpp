#ifndef DYNTRACE_FASTTP_RECLAIMER_HPP_
#define DYNTRACE_FASTTP_RECLAIMER_HPP_

#include <functional>
#include <list>
#include <set>
#include <thread>
#include <variant>
#include <vector>

#include <process/process.hpp>
#include <util/barrier.hpp>
#include <util/function.hpp>
#include <util/integer_range.hpp>
#include <util/locked.hpp>
#include <util/safe_queue.hpp>

#include <signal.h>

namespace dyntrace::fasttp
{
    class reclaimer
    {
    public:
        using predicate = dyntrace::function<bool()>;
        using deleter = dyntrace::function<void()>;

        reclaimer(const process::process* proc);
        ~reclaimer();

        void reclaim(predicate pred, deleter del, dyntrace::address_range invalid)
        {
            _queue.put(reclaim_work{std::move(pred), std::move(del), invalid});
        }

        void add_invalid(dyntrace::address_range range) noexcept
        {
            auto inv = _always_invalid.lock();
            inv->push_back(range);
        }

    private:
        struct reclaim_stop {};
        struct reclaim_work
        {
            std::function<bool()> predicate;
            std::function<void()> deleter;
            dyntrace::address_range invalid;
        };
        using queue_element = std::variant<std::monostate, reclaim_stop, reclaim_work>;

        struct reclaim_data
        {
            reclaimer* self;
            dyntrace::locked<std::set<dyntrace::address_range>> invalids;
            dyntrace::barrier barrier;
            std::once_flag once_flag;
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
        const process::process* _proc;
    };
}

#endif