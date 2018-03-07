#ifndef DYNTRACE_INJECT_COMMON_HPP_
#define DYNTRACE_INJECT_COMMON_HPP_

#include "dyntrace/process/process.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace dyntrace::inject
{
    inline constexpr size_t max_remote_args = 6;
    using remote_args = uintptr_t[max_remote_args];

    using process_ptr = std::shared_ptr<const process::process>;
}

#endif