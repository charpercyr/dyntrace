#include "error.hpp"
#include "fasttp.hpp"

using namespace dyntrace::fasttp;

tracepoint::~tracepoint()
{
    if(_auto_remove)
        remove();
}

void tracepoint::remove()
{
    _auto_remove = false;
    if(_impl)
    {
        _ctx->remove(_impl->location());
        _impl = nullptr;
    }
}

context::~context() = default;

tracepoint context::create(const location &loc, handler &&handler, options&& ops)
{
    auto tracepoints = _tracepoints.lock();
    void* addr = loc.resolve(_impl.process());
    if(tracepoints->find(addr) != _tracepoints->end())
    {
        throw fasttp_error{"Tracepoint already exists at " + to_hex_string(addr)};
    }
    auto it = tracepoints->insert(
        std::make_pair(addr, std::make_unique<arch_tracepoint>(addr, _impl, std::move(handler), std::move(ops)))
    ).first;
    return tracepoint{it->second.get(), this, !ops.disable_auto_remove};
}

void context::remove(void *ptr)
{
    auto tracepoints = _tracepoints.lock();
    auto it = tracepoints->find(ptr);
    if(it == tracepoints->end())
    {
        throw fasttp_error("Tracepoint " + to_hex_string(ptr) + " does not exist");
    }
    tracepoints->erase(it);
}