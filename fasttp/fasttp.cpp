#include "error.hpp"
#include "fasttp.hpp"

#include "context.hpp"

using namespace dyntrace::fasttp;

tracepoint::tracepoint(const location &loc, handler handler, const options &ops)
    : _impl{context::instance().create(loc, std::move(handler), ops)}, _auto_remove{!ops.disable_auto_remove}
{
}

void tracepoint::remove()
{
    _auto_remove = false;
    if(_impl)
    {
        context::instance().destroy(_impl);
        _impl = nullptr;
    }
}