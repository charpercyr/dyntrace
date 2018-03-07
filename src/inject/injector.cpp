#include "dyntrace/inject/injector.hpp"

#include <dlfcn.h>

using namespace dyntrace::inject;

injector::injector(process_ptr proc)
    : _e{std::move(proc)}
{
    _malloc = make_malloc(_e);
    _dlopen = _e.create<remote_ptr(remote_ptr, int)>("__libc_dlopen_mode", std::regex{".*libc.*"});
    _dlclose = _e.create<int(remote_ptr)>("__libc_dlclose", std::regex{".*libc.*"});
}

remote_ptr injector::inject(const std::string &path)
{
    auto remote_path = _malloc(path.size() + 1);
    _e.copy(remote_path.get(), path.c_str(), path.size() + 1);
    auto handle = _dlopen(remote_path.get(), RTLD_LAZY);
    if(!handle)
        throw inject_error{"Could not load " + path};
    return handle;
}

void injector::remove(remote_ptr lib)
{
    _dlclose(lib);
}