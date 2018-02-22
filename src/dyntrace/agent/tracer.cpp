#include "tracer.hpp"

#include "config.hpp"

#include <dlfcn.h>
#include <experimental/filesystem>

using namespace dyntrace::agent;
namespace fs = std::experimental::filesystem;

tracer::tracer(const std::string &name)
{
    using namespace std::string_literals;
    auto tracer_path = fs::path{dyntrace::config::tracer_directory} / fs::path{name + ".so"s};
    if(!fs::exists(tracer_path))
    {
        if(!fs::exists(tracer_path = fs::path{name}))
            throw tracer_error{"Could not find tracer "s + name};
    }
    _handle = dlopen(tracer_path.c_str(), RTLD_LAZY);
    if(!_handle)
        throw tracer_error{"Could not open tracer "s + name};
    _factory = reinterpret_cast<handler_factory>(dlsym(_handle, "create_handler"));
    if(!_factory)
    {
        dlclose(_handle);
        throw tracer_error{"Could not find create_handler in tracer "s + name};
    }
}

tracer::~tracer()
{
    if(_handle)
        dlclose(_handle);
}

tracer& tracer::operator=(tracer &&t) noexcept
{
    if(_handle)
        dlclose(_handle);
    _handle = t._handle;
    _factory = t._factory;
    t._handle = nullptr;
    return *this;
}

tracepoint_handler tracer::create_handler(const std::vector<std::string>& args)
{
    return _factory(args);
}

tracepoint_handler tracer_registry::create_handler(const std::string &tracer, const std::vector<std::string> &args)
{
    auto it = _tracers.find(tracer);
    if(it == _tracers.end())
    {
        it = _tracers.emplace(
            std::piecewise_construct,
            std::make_tuple(tracer),
            std::make_tuple(tracer)
        ).first;
    }
    return it->second.create_handler(args);
}