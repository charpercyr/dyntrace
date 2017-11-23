#include "error.hpp"
#include "fasttp.hpp"

using namespace dyntrace::fasttp;

tracepoint::~tracepoint()
{
    if(_auto_remove && _impl)
        remove();
}

void tracepoint::remove()
{
    _auto_remove = false;
    _ctx->remove(_impl->location());
    _impl = nullptr;
}

context::~context() = default;

tracepoint context::create(const location &loc, handler &&handler, bool auto_remove)
{
    auto tracepoints = _tracepoints.lock();
    void* addr = loc.resolve(*_proc);
    if(tracepoints->find(addr) != _tracepoints->end())
    {
        throw fasttp_error{"Tracepoint already exists at " + to_hex_string(addr)};
    }
    auto it = tracepoints->insert(std::make_pair(addr, std::make_unique<arch_tracepoint>(addr, *_proc, std::move(handler)))).first;
    return tracepoint{it->second.get(), this, auto_remove};
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