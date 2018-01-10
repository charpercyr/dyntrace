/**
 * Path utilities that wraps C librairies
 */
#ifndef DYNTRACE_UTIL_PATH_HPP_
#define DYNTRACE_UTIL_PATH_HPP_

#include <string>

namespace dyntrace
{
    /**
     * Gets the absolute path of an object
     */
    std::string realpath(const std::string& path);
    /**
     * Gets the path to the executable of a PID.
     */
    std::string get_executable(pid_t pid);
    /**
     * Gets the PID of an executable name.
     * @param name The name of the executable. The function returns for the first executable that contains the name.
     */
    pid_t find_process(const std::string& name);
}

#endif