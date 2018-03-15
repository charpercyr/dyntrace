#ifndef DYNTRACE_FASTTP_RECLAIMER_HPP_
#define DYNTRACE_FASTTP_RECLAIMER_HPP_

#include "dyntrace/process/process.hpp"
#include "dyntrace/util/integer_range.hpp"
#include "dyntrace/util/locked.hpp"
#include "dyntrace/util/semaphore.hpp"

#include <any>
#include <csignal>
#include <functional>
#include <future>
#include <thread>
#include <variant>
#include <vector>

namespace dyntrace::fasttp
{
    /**
     * Object that is in charge of deleting tracepoint code once we are sure it is not in use.
     */
    class reclaimer
    {
    public:

        static reclaimer& instance();

        using predicate_type = std::function<bool(uintptr_t)>;
        using deleter_type = std::function<void()>;
        struct reclaim_request
        {
            predicate_type pred;
            deleter_type del;
            std::any data;
        };

        reclaimer() noexcept;
        ~reclaimer();

        void reclaim(uintptr_t id, reclaim_request&& req);
        void add_invalid(dyntrace::address_range range) noexcept;
        std::optional<reclaim_request> cancel(uintptr_t id);

    private:
        using request_map = std::unordered_map<uintptr_t, std::shared_ptr<reclaim_request>>;
        using locked_request_map = dyntrace::locked<request_map>;

        void run();

        void reclaim_batch(locked_request_map::proxy_type&& to_remove);
        void reclaim_batch(request_map&& to_remove);
        void wait_last();
        static void on_usr1(int, siginfo_t* sig, void* ctx);

        dyntrace::semaphore _events{0};
        std::atomic<bool> _stop{false};
        locked_request_map _to_remove;
        dyntrace::shared_locked<std::vector<dyntrace::address_range>> _always_invalid;
        std::thread _thread;
    };
}

#endif