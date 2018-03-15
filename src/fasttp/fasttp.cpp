#include "dyntrace/fasttp/fasttp.hpp"

#include "arch/tracepoint.hpp"

using namespace dyntrace::fasttp;

void* dyntrace::fasttp::resolve(const location& loc)
{
    if(std::holds_alternative<addr_location>(loc))
    {
        return std::get<addr_location>(loc);
    }
    else if(std::holds_alternative<symbol_location>(loc))
    {
        auto sym = dyntrace::process::process::this_process().get(std::get<symbol_location>(loc));
        return reinterpret_cast<void*>(sym.value);
    }
    else
    {
        return nullptr;
    }
}

tracepoint::tracepoint(const fasttp::location &loc, handler handler, const options &ops)
    : _impl{new arch_tracepoint{
        resolve(loc),
        std::move(handler), ops
    }} {}

tracepoint::~tracepoint()
{
    delete _impl;
}

tracepoint& tracepoint::operator=(tracepoint&& tp)
{
    delete _impl;
    _impl = tp._impl;
    tp._impl = nullptr;
    return *this;
}

void tracepoint::enable(bool e) noexcept
{
    if(e)
        _impl->enable();
    else
        _impl->disable();
}

void tracepoint::disable() noexcept
{
    _impl->disable();
}

bool tracepoint::enabled() const noexcept
{
    return _impl->enabled();
}

const void* tracepoint::location() const noexcept
{
    return _impl->location();
}