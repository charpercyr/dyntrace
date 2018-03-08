#ifndef DYNTRACE_INJECT_INJECT_HPP_
#define DYNTRACE_INJECT_INJECT_HPP_

#include <string>

namespace dyntrace::inject
{
    void inject(pid_t pid, const std::string& path);
}

#endif