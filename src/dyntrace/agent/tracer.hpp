#ifndef DYNTRACE_AGENT_TRACER_HPP_
#define DYNTRACE_AGENT_TRACER_HPP_

#include "dyntrace/arch/arch.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dyntrace::agent
{
    using tracepoint_handler = std::function<void(const void*, const dyntrace::arch::regs&)>;
    using handler_factory = tracepoint_handler(*)(const std::vector<std::string>&);

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
            : _handle{t._handle}, _factory{t._factory}
        {
            t._handle = nullptr;
        }
        tracer& operator=(tracer&& t) noexcept;

        tracepoint_handler create_handler(const std::vector<std::string>& args);

    private:
        void* _handle;
        handler_factory _factory;
    };

    class tracer_registry
    {
    public:
        tracepoint_handler create_handler(const std::string& tracer, const std::vector<std::string>& args);

    private:
        std::unordered_map<std::string, tracer> _tracers;
    };
}

#endif