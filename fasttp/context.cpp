#include "context.hpp"

#include <fasttp/error.hpp>

using namespace dyntrace::fasttp;

context& context::instance()
{
    static context ctx;
    return ctx;
}

context::context()
    : _proc{getpid()}, _impl{this}, _reclaimer{&_proc}
{

}

arch_tracepoint* context::create(const location &loc, handler handler, const options &ops)
{
    auto tracepoints = _tracepoints.lock();
    void* addr = loc.resolve(_proc);
    if(tracepoints->find(addr) != _tracepoints->end())
    {
        throw fasttp_error{"Tracepoint already exists at " + to_hex_string(addr)};
    }
    auto it = tracepoints->insert(
        std::make_pair(addr, std::make_unique<arch_tracepoint>(addr, this, std::move(handler), ops))
    ).first;
    return it->second.get();
}

void context::destroy(arch_tracepoint *tp)
{
    auto tracepoints = _tracepoints.lock();
    auto it = tracepoints->find(tp->location());
    if(it != tracepoints->end() && it->second.get() == tp)
    {
        it->second->disable();
        _reclaimer.reclaim(
            [tp]() -> bool
            {
                return tp->refcount() == 0;
            },
            [tp = std::move(it->second)]() mutable -> void
            {
                tp = nullptr;
            },
            tp->range()
        );
        tracepoints->erase(it);
    }
    else
        throw fasttp_error("Tracepoint " + to_hex_string(tp->location()) + " does not exist");
}