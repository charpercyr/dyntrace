#include "context.hpp"

#include <fasttp/error.hpp>

using namespace dyntrace::fasttp;

context& context::instance() noexcept
{
    static context ctx;
    return ctx;
}

context::context() noexcept
    : _impl{this}, _reclaimer{}
{

}