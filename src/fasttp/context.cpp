#include "context.hpp"

#include "arch/tracepoint.hpp"

#include "dyntrace/fasttp/error.hpp"

using namespace dyntrace::fasttp;

context& context::instance() noexcept
{
    static context ctx;
    return ctx;
}

context::context() noexcept
    : _impl{std::make_unique<arch_context>(this)}
{

}