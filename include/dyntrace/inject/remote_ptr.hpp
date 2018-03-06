#ifndef DYNTRACE_INJECT_REMOTE_PTR_HPP_
#define DYNTRACE_INJECT_REMOTE_PTR_HPP_

#include "dyntrace/util/ptr_wrapper.hpp"

namespace dyntrace::inject
{
    struct remote_ptr_tag;
    using remote_ptr = dyntrace::ptr_wrapper<remote_ptr_tag>;
}

#endif