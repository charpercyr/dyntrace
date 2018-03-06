#ifndef DYNTRACE_INJECT_COMMON_HPP_
#define DYNTRACE_INJECT_COMMON_HPP_

#include <cstddef>
#include <cstdint>

namespace dyntrace::inject
{
    inline constexpr size_t max_remote_args = 6;
    using remote_args = uintptr_t[max_remote_args];
}

#endif