#ifndef DYNTRACE_AGENT_COMMON_HPP_
#define DYNTRACE_AGENT_COMMON_HPP_

#include <stdexcept>

namespace dyntrace::agent
{
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
}

#define DYNTRACE_AGENT_CREATE_ERROR(category) \
struct category : public dyntrace::agent::agent_error \
{ \
    public: \
    category(const std::string& msg = "")\
        : dyntrace::agent::agent_error{#category, msg} {}\
};

#endif