#ifndef DYNTRACE_FASTTP_CODE_PTR_HPP_
#define DYNTRACE_FASTTP_CODE_PTR_HPP_

#include "dyntrace/util/ptr_wrapper.hpp"

namespace dyntrace::fasttp
{
    struct code_ptr_tag;
    using code_ptr = dyntrace::ptr_wrapper<code_ptr_tag>;
}

#endif