#include "dyntrace/inject/inject.hpp"

#include "dyntrace/inject/injector.hpp"

using namespace dyntrace::inject;

void dyntrace::inject::inject(pid_t pid, const std::string &path)
{
    injector inj{pid};
    inj.inject(path);
}