#ifndef DYNTRACE_PROCESS_ERROR_HPP_
#define DYNTRACE_PROCESS_ERROR_HPP_

#include <stdexcept>

namespace dyntrace::process
{
    class ProcessError : public std::runtime_error
    {
    public:
        ProcessError(const std::string& msg)
            : std::runtime_error("ProcessError: " + msg) {}
    };
}

#endif