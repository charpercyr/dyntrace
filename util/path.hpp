#ifndef DYNTRACE_UTIL_PATH_HPP_
#define DYNTRACE_UTIL_PATH_HPP_

#include <string>

namespace dyntrace
{
    std::string realpath(const std::string& path);
    std::string get_executable(pid_t pid);
    pid_t find_process(const std::string& name);
}

#endif