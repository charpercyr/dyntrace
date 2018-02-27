#ifndef DYNTRACE_AGENT_TRACER_HPP_
#define DYNTRACE_AGENT_TRACER_HPP_

#include "dyntrace/tracer.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dyntrace::agent
{
    using point_handler_factory = dyntrace::tracer::point_handler(*)(const std::vector<std::string>&);
    using entry_exit_handler_factory = dyntrace::tracer::entry_exit_handler(*)(const std::vector<std::string>&);

    struct agent_error : public std::runtime_error
    {
    public:
        explicit agent_error(const std::string& category, const std::string& msg = "") noexcept
            : std::runtime_error{msg}, _category{category} {}

        const std::string& category() const noexcept
        {
            return _category;
        }

    private:
        std::string _category;
    };

    class tracer_error : public agent_error
    {
    public:
        explicit tracer_error(const std::string& msg = "") noexcept
            : agent_error{"tracer_error", msg} {}
    };

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