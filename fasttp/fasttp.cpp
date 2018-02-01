#include "fasttp.hpp"

using namespace dyntrace::fasttp;

tracepoint::tracepoint(const location &loc, handler handler, const options &ops)
    : _impl{std::make_unique<arch_tracepoint>(
        loc.resolve(process::process::this_process()),
        std::move(handler), ops
    )}
{}