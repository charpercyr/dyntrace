#include "error.hpp"
#include "fasttp.hpp"

#include "context.hpp"

using namespace dyntrace::fasttp;

tracepoint::tracepoint(const location &loc, handler handler, const options &ops)
    : _impl{arch_tracepoint::make(
        loc.resolve(process::process::this_process()),
        std::move(handler), ops,
        [](arch_tracepoint* tp)
        {
            context::instance().get_reclaimer().reclaim(
                [tp]()
                {
                    return tp->refcount() == 0;
                },
                [tp]()
                {
                    delete tp;
                },
                tp->range()
            );
        }
    )}
{}

tracepoint::~tracepoint()
{
    _impl->disable();
    _impl = nullptr;
}