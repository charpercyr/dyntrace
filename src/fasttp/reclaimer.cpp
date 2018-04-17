#include "reclaimer.hpp"

#include "dyntrace/fasttp/error.hpp"

#include <unordered_set>
#include <syscall.h>
#include <sys/ucontext.h>

using namespace dyntrace::fasttp;
using namespace std::chrono_literals;

inline constexpr auto reclaim_period = 5s;
inline constexpr auto reclaim_count = 2000;

reclaimer& reclaimer::instance()
{
    static reclaimer r;
    return r;
}

reclaimer::reclaimer() noexcept
{
    static std::once_flag once_flag;
    std::call_once(once_flag, []()
    {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = &reclaimer::on_usr1;
        sigaction(SIGUSR1, &sa, nullptr);
    });
    _thread = std::thread{&reclaimer::run, this};
}

reclaimer::~reclaimer()
{
    _stop = true;
    _events.put();
    _thread.join();
}

void reclaimer::add_invalid(dyntrace::address_range range) noexcept
{
    auto inv = _always_invalid.lock();
    inv->push_back(range);
}

void reclaimer::reclaim(uintptr_t id, reclaim_request&& req)
{
    auto to_remove = _to_remove.lock();
    to_remove->emplace(
        id,
        std::shared_ptr<reclaim_request>{
            new reclaim_request{std::move(req)},
            [](reclaim_request* data)
            {
                if(data->del)
                    data->del();
                delete data;
            }
        }
    );
    _events.put();
}

std::optional<reclaimer::reclaim_request> reclaimer::cancel(uintptr_t id)
{
    auto to_remove = _to_remove.lock();
    auto it = to_remove->find(id);
    if(it != to_remove->end())
    {
        auto req = std::move(*it->second);
        to_remove->erase(it);
        return std::move(req);
    }
    return std::nullopt;
}

void reclaimer::run()
{
    auto end = std::chrono::steady_clock::now() + reclaim_period;
    while(true)
    {
        bool not_timeout = _events.wait_until(end);
        if(_stop.load(std::memory_order_relaxed))
        {
            // The only time this is called is when the program is closing
            // These functions cause problems because of the order of global delete
            auto to_remove = _to_remove.lock();
            for(auto& tr : *to_remove)
                tr.second->del = nullptr;
            break;
        }
        if(not_timeout)
        {
            auto to_remove = _to_remove.lock();
            if(to_remove->size() >= reclaim_count)
            {
                reclaim_batch(std::move(to_remove));
                end = std::chrono::steady_clock::now() + reclaim_period;
            }
        }
        else
        {
            reclaim_batch(_to_remove.lock());
            end = std::chrono::steady_clock::now() + reclaim_period;
        }
    }
}

void reclaimer::reclaim_batch(locked_request_map::proxy_type&& to_remove_proxy)
{
    if(to_remove_proxy->empty())
        return;
    request_map to_remove = std::move(*to_remove_proxy);
    to_remove_proxy->clear();
    to_remove_proxy.unlock();
    reclaim_batch(std::move(to_remove));
}

namespace
{

    void do_nothing() {}

    class reclaim_barrier
    {
    public:

        void reclaim_enter(std::function<void()> f)
        {
            dyntrace_assert(f);
            std::unique_lock lock{_lock};
            while(_count)
                _cond.wait(lock);
            dyntrace_assert(!_on_done);
            _on_done = std::move(f);
            ++_count;
        }

        void worker_enter()
        {
            std::unique_lock lock{_lock};
            dyntrace_assert(_on_done);
            ++_count;
        }

        void exit()
        {
            std::unique_lock lock{_lock};
            if(--_count == 0)
            {
                _on_done();
                _on_done = nullptr;
                lock.unlock();
                _cond.notify_one();
            }
        }

    private:
        std::mutex _lock;
        std::condition_variable _cond;
        uintptr_t _count{0};
        std::function<void()> _on_done;
    };

    class reclaim_lock
    {
    public:
        explicit reclaim_lock(reclaim_barrier& b, std::function<void()> f = do_nothing)
            : _b{b}
        {
            _b.reclaim_enter(std::move(f));
        }
        ~reclaim_lock()
        {
            _b.exit();
        }
    private:
        reclaim_barrier& _b;
    };

    class worker_lock
    {
    public:
        explicit worker_lock(reclaim_barrier& b)
            : _b{b}
        {
            _b.worker_enter();
        }
        ~worker_lock()
        {
            _b.exit();
        }
    private:
        reclaim_barrier& _b;
    };

    namespace current
    {
        reclaim_barrier barrier;
        std::promise<void> ready{};
        std::vector<std::pair<uintptr_t, std::shared_ptr<reclaimer::reclaim_request>>> to_delete;

        void cleanup()
        {
            to_delete.clear();
        }
    }

    pid_t gettid() noexcept
    {
        return syscall(SYS_gettid);
    }

    int tgkill(pid_t tgid, pid_t tid, int sig)
    {
        return syscall(SYS_tgkill, tgid, tid, sig);
    }
}

void reclaimer::reclaim_batch(reclaimer::request_map&& to_remove)
{
    reclaim_lock lock{current::barrier, current::cleanup};
    current::ready = {};
    auto ready = current::ready.get_future();

    std::copy(to_remove.begin(), to_remove.end(), std::back_inserter(current::to_delete));

    for(auto tid : process::process::this_process().threads())
    {
        if(tid != gettid())
            tgkill(getpid(), tid, SIGUSR1);
    }

    // If we wait too long, we just put back the data, else it is deleted.
    // It means that no other thread can be signaled with SIGUSR1 (weird)
    if(ready.wait_for(reclaim_period) == std::future_status::timeout)
    {
        auto _tr = _to_remove.lock();
        for(auto&& tr : to_remove)
        {
            _tr->insert(std::move(tr));
        }
    }
}

void reclaimer::wait_last()
{
    reclaim_lock lock{current::barrier};
    auto to_remove = _to_remove.lock();
    for(auto&& tr : *to_remove)
    {
        tr.second->del = nullptr;
    }
}

#ifdef __i386__
#define REG_IP uc_mcontext.gregs[REG_EIP]
#elif __x86_64__
#define REG_IP uc_mcontext.gregs[REG_RIP]
#elif __arm__
#define REG_IP uc_mcontext.arm_pc
#endif

void reclaimer::on_usr1(int, siginfo_t* sig, void* _ctx)
{
    worker_lock lock{current::barrier};
    try
    {
        current::ready.set_value();
    }
    catch(std::future_error&)
    {
        // Nothing
    }

    uintptr_t rip = reinterpret_cast<ucontext_t*>(_ctx)->REG_IP;

    {
        auto always_invalid = instance()._always_invalid.lock_shared();
        for(auto&& ai : *always_invalid)
        {
            if(ai.contains(rip))
            {
                auto _tr = instance()._to_remove.lock();
                for(auto&& tr : current::to_delete)
                {
                    _tr->insert(tr);
                }
                break;
            }
        }
    }

    for(auto&& td : current::to_delete)
    {
        if(!td.second->pred(rip))
        {
            auto tr = instance()._to_remove.lock();
            auto it = tr->find(td.first);
            if(it == tr->end())
                tr->insert(td);
        }
    }
}