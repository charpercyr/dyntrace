/**
 * Base class for all the exceptions in the project
 */

#ifndef DYNTRACE_UTIL_ERROR_HPP_
#define DYNTRACE_UTIL_ERROR_HPP_

#include <stdexcept>

namespace dyntrace
{
    struct dyntrace_error : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

}
// Creates a class that inherits from dyntrace::dyntrace_error
#define DYNTRACE_CREATE_ERROR(name) \
struct name : ::dyntrace::dyntrace_error \
{\
    explicit name(const std::string& msg)\
        : ::dyntrace::dyntrace_error{#name": " + msg} {}\
}

#endif