#include "dyntrace/fasttp/fasttp.hpp"

#include "arch/tracepoint.hpp"

using namespace dyntrace::fasttp;

tracepoint::tracepoint(void* loc, handler handler, const options &ops)
    : _impl{new arch_tracepoint{
        loc,
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