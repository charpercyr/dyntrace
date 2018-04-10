#include "dyntrace/inject/injector.hpp"

#include "config.hpp"

#include <dlfcn.h>

using namespace dyntrace::inject;

namespace
{
}

injector::injector(process_ptr proc)
    : _e{std::move(proc)}
{
    using namespace std::string_literals;
    _malloc = make_malloc(_e);

    auto libc_dlopen = _e.create<remote_ptr(remote_ptr, int)>("__libc_dlopen_mode", std::regex{".*libc-.*\\.so"});
    auto remove_dlwrapper_library = _malloc(strlen(dlwrapper_library) + 1);
    _e.copy(remove_dlwrapper_library.get(), dlwrapper_library, strlen(dlwrapper_library) + 1);
    auto h = libc_dlopen(remove_dlwrapper_library.get(), RTLD_LAZY);
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
        throw inject_error{"Could not load "s + path};
    return handle;
}

void injector::remove(remote_ptr lib)
{
    _dlclose(lib);
}