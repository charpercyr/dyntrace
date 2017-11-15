#include "fasttp.hpp"

#include <unordered_map>
#include <mutex>

#include <tracer.hpp>

using namespace dyntrace::fasttp;

namespace registry
{
    namespace
    {
        struct entry
        {
            void *at;
            handler h;
        };

        std::mutex _reg_mutex;
        std::unordered_map<void *, entry> _reg;

        void add(entry &&e)
        {
            auto lock = std::lock_guard{_reg_mutex};
            _reg.emplace(e.at, std::move(e));
        }

        void remove(void *at)
        {
            auto lock = std::lock_guard{_reg_mutex};
            _reg.erase(at);
        }

        entry* get(void *at)
        {
            auto it = _reg.find(at);
            if(it != _reg.end())
            {
                return &it->second;
            }
            else
            {
                return nullptr;
            }
        }
    }
}

namespace
{
    void handle_tracepoint(void* caller, const dyntrace::tracer::regs& r)
    {
        if(auto e = registry::get(caller))
        {
            e->h(caller, r);
        }
    }
}

void tracepoint::do_insert(handler &&h)
{

}

void tracepoint::do_remove()
{

}