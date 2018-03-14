#include "dyntrace/fasttp/reclaimer.hpp"

#include "dyntrace/fasttp/error.hpp"

#include <unordered_set>
#include <syscall.h>
#include <sys/ucontext.h>

using namespace dyntrace::fasttp;
using namespace std::chrono_literals;

inline constexpr auto reclaim_period = 5s;
inline constexpr auto reclaim_count = 2000;

class reclaim_failed : public std::runtime_error
{
public:
    reclaim_failed() noexcept
        : std::runtime_error{"reclaim failed"} {}
};

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
    std::thread th{&reclaimer::run, this};
    th.detach();
}

reclaimer::~reclaimer()
{
    _stop = true;
    _events.put();
}

void reclaimer::add_invalid(dyntrace::address_range range) noexcept
{
    auto inv = _always_invalid.lock();
    inv->push_back(range);
}

void reclaimer::reclaim(uintptr_t id, reclaimer::predicate_type pred, reclaimer::deleter_type del, std::any data)
{
    auto to_remove = _to_remove.lock();
    to_remove->emplace(id, to_remove_data{std::move(pred), std::move(del), std::move(data)});
    _events.put();
}

std::optional<std::any> reclaimer::cancel(uintptr_t id)
{
    auto to_remove = _to_remove.lock();
    auto it = to_remove->find(id);
    if(it != to_remove->end())
    {
        std::any data = std::move(it->second.data);
        to_remove->erase(it);
        return std::move(data);
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
            auto to_remove = _to_remove.lock();
            reclaim_batch(std::move(*to_remove));
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

void reclaimer::reclaim_batch(locked_to_remove_type::proxy_type&& to_remove_proxy)
{
    if(to_remove_proxy->empty())
        return;
    to_remove_type to_remove = std::move(*to_remove_proxy);
    to_remove_proxy->clear();
    to_remove_proxy.unlock();
    try
    {
        reclaim_batch(std::move(to_remove));
    }
    catch(const reclaim_failed&)
    {
        // If the reclaim failed for some reason, we put back the reclaim data
        to_remove_proxy = _to_remove.lock();
        to_remove_proxy->insert(to_remove.begin(), to_remove.end());
    }
}

namespace
{
    namespace current
    {
        std::mutex lock;
        reclaimer* self;
        std::unique_ptr<dyntrace::barrier> barrier;
        reclaimer::to_remove_type* to_remove;
        dyntrace::locked<std::unordered_set<uintptr_t>> cant_remove;
    }
    pid_t gettid() noexcept
    {
        return syscall(SYS_gettid);
    }

    int signal_thread(pid_t tid, int sig)
    {
        return syscall(SYS_tgkill, getpid(), tid, sig);
    }
}

void reclaimer::reclaim_batch(reclaimer::to_remove_type&& to_remove)
{
    std::unique_lock lock{current::lock};
    current::self = this;
    current::to_remove = &to_remove;

    auto ths = dyntrace::process::process::this_process().threads();
    current::barrier = std::make_unique<dyntrace::barrier>(ths.size());
    for(auto tid : ths)
    {
        if(tid != gettid())
        {
            if(signal_thread(tid, SIGUSR1) == -1)
            {
                current::barrier->cancel();
                throw reclaim_failed{};
            }
        }
    }

    current::barrier->wait();
    if(!current::barrier->wait())
    {
        throw reclaim_failed{};
    }
    current::barrier->wait();

    auto cant_remove = current::cant_remove.lock();
    for(auto&& tr : to_remove)
    {
        if(cant_remove->find(tr.first) == cant_remove->end())
            tr.second.del();
        else
        {
            auto self_to_remove = _to_remove.lock();
            self_to_remove->insert(std::move(tr));
        }
    }

    cant_remove->clear();
    current::barrier = nullptr;
    current::to_remove = nullptr;
    current::self = nullptr;
}

#ifdef __i386__
#define REG_IP REG_EIP
#else
#define REG_IP REG_RIP
#endif

void reclaimer::on_usr1(int, siginfo_t* sig, void* _ctx)
{
    if(!current::barrier->wait())
        return;

    auto ctx = reinterpret_cast<ucontext_t*>(_ctx);
    auto rip = static_cast<uintptr_t>(ctx->uc_mcontext.gregs[REG_IP]);

    {
        auto always_invalid = current::self->_always_invalid.lock_shared();
        for (auto&& ai : *always_invalid)
        {
            if (ai.contains(rip))
            {
                current::barrier->cancel();
                return;
            }
        }
    }

    if(!current::barrier->wait())
        return;

    for(const auto& tr : *current::to_remove)
    {
        if(!tr.second.pred(rip))
        {
            auto cant_remove = current::cant_remove.lock();
            cant_remove->insert(tr.first);
        }
    }

    current::barrier->wait();
}