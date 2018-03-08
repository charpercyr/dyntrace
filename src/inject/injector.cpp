#include "dyntrace/inject/injector.hpp"

#include <dlfcn.h>

using namespace dyntrace::inject;

injector::injector(process_ptr proc)
    : _e{std::move(proc)}
{
    _malloc = make_malloc(_e);

    static constexpr const char* libdl_path = "libdl.so";
    auto libc_dlopen = _e.create<remote_ptr(remote_ptr, int)>("__libc_dlopen_mode", std::regex{".*libc.*"});
    auto remote_libdl_path = _malloc(strlen(libdl_path) + 1);
    _e.copy(remote_libdl_path.get(), libdl_path, strlen(libdl_path) + 1);
    auto h = libc_dlopen(remote_libdl_path.get(), RTLD_NOW);
    if(!h)
        throw inject_error{"Could not load libdl"};
    _dlopen = _e.create<remote_ptr(remote_ptr, int)>("dlopen", std::regex{".*libdl.*"});
    _dlclose = _e.create<int(remote_ptr)>("dlclose", std::regex{".*libdl.*"});
}

remote_ptr injector::inject(const std::string &path)
{
    using namespace std::string_literals;
    auto remote_path = _malloc(path.size() + 1);
    _e.copy(remote_path.get(), path.c_str(), path.size() + 1);
    auto handle = _dlopen(remote_path.get(), RTLD_LAZY);
    if(!handle)
    {
        throw inject_error{"Could not load "s + path};
    }
    return handle;
}

void injector::remove(remote_ptr lib)
{
    _dlclose(lib);
}