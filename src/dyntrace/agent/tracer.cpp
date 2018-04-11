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
    _handle = dlopen(tracer_path.c_str(), RTLD_LAZY);
    if(!_handle)
    {
        _handle = dlopen(name.c_str(), RTLD_LAZY);
        if(!_handle)
            throw tracer_error{"Could not open tracer "s + name};
    }
    _point_factory = reinterpret_cast<point_handler_factory>(dlsym(_handle, "create_point_handler"));
    _entry_exit_factory = reinterpret_cast<entry_exit_handler_factory>(dlsym(_handle, "create_entry_exit_handler"));
    if(!_point_factory && !_entry_exit_factory)
    {
        dlclose(_handle);
        throw tracer_error{"Invalid tracer "s + name};
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
    _point_factory = t._point_factory;
    t._handle = nullptr;
    return *this;
}

dyntrace::tracer::point_handler tracer::create_point_handler(const std::vector<std::string>& args)
{
    if(_point_factory)
        return _point_factory(args);
    else
        throw std::runtime_error{"Point handler not supported"};
}

dyntrace::tracer::entry_exit_handler tracer::create_entry_exit_handler(const std::vector<std::string>& args)
{
    if(_entry_exit_factory)
        return _entry_exit_factory(args);
    else
        throw std::runtime_error{"Entry/Exit handler not supported"};
}

tracer& tracer_registry::get_factory(const std::string& tracer){
    auto it = _tracers.find(tracer);
    if(it == _tracers.end())
    {
        it = _tracers.emplace(
            std::piecewise_construct,
            std::make_tuple(tracer),
            std::make_tuple(tracer)
        ).first;
    }
    return it->second;
}