#include "error.hpp"
#include "fasttp.hpp"

#include "context.hpp"

using namespace dyntrace::fasttp;

tracepoint::tracepoint(const location &loc, handler handler, const options &ops)
    : _impl{create(loc, std::move(handler), ops)}
{

}

tracepoint::~tracepoint()
{
    _impl->disable();
}

std::shared_ptr<arch_tracepoint> tracepoint::create(const location &loc, handler &&handler, const options &ops)
{
    return std::shared_ptr<arch_tracepoint>(
        new arch_tracepoint{loc.resolve(process::process::this_process()), std::move(handler), ops},
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
    );
}