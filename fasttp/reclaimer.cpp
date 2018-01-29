#include "reclaimer.hpp"

#include <syscall.h>
#include <sys/ucontext.h>

using namespace dyntrace::fasttp;
using namespace std::chrono_literals;

inline constexpr auto reclaim_period = 5s;

reclaimer::reclaim_data* reclaimer::_reclaim_data{nullptr};
std::mutex reclaimer::_reclaim_lock;

reclaimer::reclaimer(const process::process* proc)
    : _thread{&reclaimer::run, this}, _proc{proc}
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
                _batch.push_back(std::move(std::get<reclaim_work>(next)));
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
    if(_batch.empty())
        return;
    std::unique_lock lock{_reclaim_lock};

    auto ths = _proc->threads();

    _reclaim_data = new reclaim_data{
        this,
        {},
        dyntrace::barrier{ths.size()},
        {}
    };

    for(auto pid : ths)
    {
        // DO NOT SEND SIGNAL TO SELF, IT WILL PROBABLY DEADLOCK
        if(pid != syscall(SYS_gettid))
            syscall(SYS_tgkill, getpid(), pid, SIGUSR1);
    }
    _reclaim_data->barrier.wait();

    {
        auto inv = _reclaim_data->invalids.lock();
        for (auto it = _reclaim_data->self->_batch.begin(); it != _reclaim_data->self->_batch.end();)
        {
            if (inv->find(it->invalid) == inv->end())
            {
                auto to_del = it++;
                to_del->deleter();
                _reclaim_data->self->_batch.erase(to_del);
                continue;
            }
            ++it;
        }
    }

    delete _reclaim_data;
}

void reclaimer::on_usr1(int, siginfo_t* sig, void* _ctx)
{
    if(_reclaim_data)
    {
        auto ctx = reinterpret_cast<ucontext_t*>(_ctx);
        auto rip = static_cast<uintptr_t>(ctx->uc_mcontext.gregs[REG_RIP]);

        std::call_once(_reclaim_data->once_flag, [self = _reclaim_data->self, &invalids = _reclaim_data->invalids]()
        {
            for(auto& b : self->_batch)
            {
                if(!b.predicate())
                {
                    auto inv = invalids.lock();
                    inv->insert(b.invalid);
                }
            }
        });

        {
            auto ainv = _reclaim_data->self->_always_invalid.lock();
            for(auto& r : *ainv)
            {
                if(r.contains(rip))
                {
                    auto inv = _reclaim_data->invalids.lock();
                    for(auto& b : _reclaim_data->self->_batch)
                        inv->insert(b.invalid);
                }
            }
        }
        for(auto& b : _reclaim_data->self->_batch)
        {
            if (b.invalid.contains(rip))
            {
                auto inv = _reclaim_data->invalids.lock();
                inv->insert(b.invalid);
            }
        }

        _reclaim_data->barrier.wait();
    }
    else
    {
        exit(128 + SIGUSR1);
    }
}