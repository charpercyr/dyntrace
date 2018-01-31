#include "context.hpp"

#include <fasttp/error.hpp>

using namespace dyntrace::fasttp;

context& context::instance()
{
    static context ctx;
    return ctx;
}

context::context()
    : _impl{this}, _reclaimer{}
{

}