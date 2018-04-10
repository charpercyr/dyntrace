#ifndef DYNTRACE_AGENT_TRACER_HPP_
#define DYNTRACE_AGENT_TRACER_HPP_

#include "common.hpp"

#include "dyntrace/tracer.hpp"

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace dyntrace::agent
{
    using point_handler_factory = dyntrace::tracer::point_handler(*)(const std::vector<std::string>&);
    using entry_exit_handler_factory = dyntrace::tracer::entry_exit_handler(*)(const std::vector<std::string>&);

    DYNTRACE_AGENT_CREATE_ERROR(tracer_error);

    class tracer
    {
    public:
        tracer(const tracer&) = delete;
        tracer& operator=(const tracer&) = delete;

        explicit tracer(const std::string& name);
        ~tracer();

        tracer(tracer&& t) noexcept
            : _handle{t._handle}, _point_factory{t._point_factory}, _entry_exit_factory{t._entry_exit_factory}
        {
            t._handle = nullptr;
        }
        tracer& operator=(tracer&& t) noexcept;

        dyntrace::tracer::point_handler create_point_handler(const std::vector<std::string>& args);
        dyntrace::tracer::entry_exit_handler create_entry_exit_handler(const std::vector<std::string>& args);

    private:
        void* _handle;
        point_handler_factory _point_factory;
        entry_exit_handler_factory _entry_exit_factory;
    };

    class tracer_registry
    {
    public:
        tracer& get_factory(const std::string& tracer);

    private:
        std::unordered_map<std::string, tracer> _tracers;
    };
}

#endif