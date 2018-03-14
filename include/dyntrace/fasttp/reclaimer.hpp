#ifndef DYNTRACE_FASTTP_RECLAIMER_HPP_
#define DYNTRACE_FASTTP_RECLAIMER_HPP_

#include "dyntrace/process/process.hpp"
#include "dyntrace/util/barrier.hpp"
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
        using predicate_type = std::function<bool(uintptr_t)>;
        using deleter_type = std::function<void()>;
        struct to_remove_data
        {
            predicate_type pred;
            deleter_type del;
            std::any data;
        };
        using to_remove_type = std::unordered_map<uintptr_t, to_remove_data>;
        using locked_to_remove_type = dyntrace::locked<to_remove_type>;

        reclaimer() noexcept;
        ~reclaimer();

        void reclaim(uintptr_t id, predicate_type pred, deleter_type del, std::any data = {});
        void add_invalid(dyntrace::address_range range) noexcept;
        std::optional<std::any> cancel(uintptr_t id);

    private:

        void run();

        void reclaim_batch(locked_to_remove_type::proxy_type&& to_remove);
        void reclaim_batch(to_remove_type&& to_remove);
        static void on_usr1(int, siginfo_t* sig, void* ctx);

        dyntrace::semaphore _events{0};
        std::atomic<bool> _stop{false};
        locked_to_remove_type _to_remove;
        dyntrace::shared_locked<std::vector<dyntrace::address_range>> _always_invalid;
    };
}

#endif