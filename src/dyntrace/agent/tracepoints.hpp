#ifndef DYNTRACE_DYNTRACE_AGENT_TRACEPOINTS_HPP_
#define DYNTRACE_DYNTRACE_AGENT_TRACEPOINTS_HPP_

#include "tracer.hpp"

#include "dyntrace/fasttp/fasttp.hpp"
#include "process.pb.h"

#include <optional>
#include <unordered_map>
#include <variant>
#include <vector>

namespace dyntrace::agent
{
    DYNTRACE_AGENT_CREATE_ERROR(tracepoints_error);

    struct tracepoint
    {
        std::optional<std::string> symbol;
        bool failed{false};
        fasttp::tracepoint tp;
    };
    struct tracepoint_group_filter
    {
        std::string filter;
    };
    struct tracepoint_group_regex
    {
        std::string regex;
    };
    struct tracepoint_group
    {
        std::string name;
        std::variant<tracepoint_group_filter, tracepoint_group_regex, uintptr_t> location;
        fasttp::handler handler;
        bool entry_exit{false};
        std::string tracer;
        std::vector<std::string> tracer_args;
        std::vector<tracepoint> tps;
        size_t active{0};
    };

    class tracepoint_registry
    {
    public:
        using add_status = std::pair<std::string, std::vector<std::pair<size_t, std::string>>>;

        add_status add(const proto::process::add_tracepoint& req);
        void remove(const proto::process::remove_tracepoint& req);

        const auto& groups() const noexcept
        {
            return _groups;
        }

    private:

        bool check_sym(void* addr);

        std::unordered_map<std::string, tracepoint_group> _groups;
        uint32_t _next_id{0};
        tracer_registry _tracers;
    };
}

#endif