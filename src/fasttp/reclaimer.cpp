#include "dyntrace/fasttp/reclaimer.hpp"

#include <syscall.h>
#include <sys/ucontext.h>

using namespace dyntrace::fasttp;
using namespace std::chrono_literals;

inline constexpr auto reclaim_period = 5s;
inline constexpr auto reclaim_count = 2000;

reclaimer::reclaim_data* reclaimer::_reclaim_data{nullptr};
std::mutex reclaimer::_reclaim_lock;

reclaimer::reclaimer() noexcept
    : _thread{&reclaimer::run, this}
{
    static std::once_flag once_flag;
    std::call_once(once_flag, []()
    {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = &reclaimer::on_usr1;
        sigaction(SIGUSR1, &sa, nullptr);
    });
}

reclaimer::~reclaimer()
{
    _queue.put(reclaim_stop{});
    _thread.join();
}

std::future<void> reclaimer::trigger_reclaim() noexcept
{
    auto p = std::make_shared<std::promise<void>>();
    auto l = [p]()
    {
        p->set_value();
    };
    _queue.put(reclaim_force{std::move(l)});
    return p->get_future();
}

void reclaimer::run()
{
    auto end = std::chrono::steady_clock::now() + reclaim_period;
    reclaimer::queue_element next;
    while(true)
    {
        if(_queue.try_pop_until(next, end))
        {
            if(std::holds_alternative<reclaim_stop>(next))
            {
                reclaim_batch();
                return;
            }
            else if(std::holds_alternative<reclaim_work>(next))
            {
                auto batch = _batch.lock();
                batch->push_back(std::move(std::get<reclaim_work>(next)));
                if(batch->size() >= reclaim_count)
                {
                    reclaim_batch();
                    end = std::chrono::steady_clock::now() + reclaim_period;
                }
            }
            else if(std::holds_alternative<reclaim_force>(next))
            {
                reclaim_batch();
                end = std::chrono::steady_clock::now() + reclaim_period;
            }
        }
        else
        {
            reclaim_batch();
            end = std::chrono::steady_clock::now() + reclaim_period;
        }
    }
}

void reclaimer::reclaim_batch()
{
    if(_batch->empty())
        return;

    std::unique_lock lock{_reclaim_lock};

    auto ths = process::process::this_process().threads();

    _reclaim_data = new reclaim_data{
        this,
        {},
        dyntrace::barrier{ths.size()},
        false
    };

    for(auto pid : ths)
    {
        // DO NOT SEND SIGNAL TO SELF, IT WILL PROBABLY DEADLOCK
        if(pid != syscall(SYS_gettid))
            syscall(SYS_tgkill, getpid(), pid, SIGUSR1);
    }
    _reclaim_data->barrier.wait();
    _reclaim_data->barrier.wait();

    {
        auto to_del = _reclaim_data->to_delete.lock();
        for(const auto& d : *to_del)
            d();
    }

    delete _reclaim_data;
}

void reclaimer::on_usr1(int, siginfo_t* sig, void* _ctx)
{
    if(_reclaim_data)
    {
        auto ctx = reinterpret_cast<ucontext_t*>(_ctx);
        auto rip = static_cast<uintptr_t>(ctx->uc_mcontext.gregs[REG_RIP]);

        {
            auto ainv = _reclaim_data->self->_always_invalid.lock();
            for(auto& r : *ainv)
            {
                if(r.contains(rip))
                {
                    _reclaim_data->cancel = true;
                }
            }
        }
        _reclaim_data->barrier.wait();
        if(_reclaim_data->cancel)
            return;

        {
            auto batch = _reclaim_data->self->_batch.lock();
            for (auto it = batch->begin(); it != batch->end();)
            {
                if (it->predicate(rip))
                {
                    auto to_del = _reclaim_data->to_delete.lock();
                    to_del->push_back(std::move(it->deleter));
                    batch->erase(it++);
                }
                else
                    ++it;
            }
        }
        _reclaim_data->barrier.wait();
    }
    else
    {
        exit(128 + SIGUSR1);
    }
}