#ifndef DYNTRACE_INJECT_ERROR_HPP_
#define DYNTRACE_INJECT_ERROR_HPP_

#include <util/error.hpp>

namespace dyntrace::inject
{
    DYNTRACE_CREATE_ERROR(inject_error);

    inline inject_error errno_inject_error(const std::string& msg) noexcept
    {
        return inject_error{msg + " (" + std::to_string(errno) + ", " + std::string{strerror(errno)} + ")"};
    }
}

#endif