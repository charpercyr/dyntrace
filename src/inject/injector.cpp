#include "dyntrace/inject/injector.hpp"

#include "config.hpp"

#include <dlfcn.h>

using namespace dyntrace::inject;

injector::injector(process_ptr proc)
    : _e{std::move(proc)}
{
    using namespace std::string_literals;
    _malloc = make_malloc(_e);

    auto libc_dlopen = _e.create<remote_ptr(remote_ptr, int)>("__libc_dlopen_mode", std::regex{".*libc.*"});
    auto remote_libdl_path = _malloc(strlen(dlwrapper_library) + 1);
    _e.copy(remote_libdl_path.get(), dlwrapper_library, strlen(dlwrapper_library) + 1);
    auto h = libc_dlopen(remote_libdl_path.get(), RTLD_LAZY);
    if(!h)
        throw inject_error{"Could not load "s + dlwrapper_library};
    _dlopen = _e.create<remote_ptr(remote_ptr, int)>("dyntrace_dlopen", std::regex{dlwrapper_library});
    _dlclose = _e.create<int(remote_ptr)>("dyntrace_dlclose", std::regex{dlwrapper_library});
}

remote_ptr injector::inject(const std::string &path)
{
    using namespace std::string_literals;
    auto remote_path = _malloc(path.size() + 1);
    _e.copy(remote_path.get(), path.c_str(), path.size() + 1);
    auto handle = _dlopen(remote_path.get(), RTLD_LAZY);
    if(!handle)
    {
        auto dlerror_ = _e.create<remote_ptr()>("dlerror", std::regex{".*libdl.*"});
        auto err = dlerror_();
        std::string err_str(32, 0);
        _e.copy(err_str.data(), err, 33);
        throw inject_error{"Could not load "s + path + ": "s + err_str};
    }
    return handle;
}

void injector::remove(remote_ptr lib)
{
    _dlclose(lib);
}