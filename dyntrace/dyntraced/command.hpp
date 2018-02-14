#ifndef DYNTRACE_DYNTRACED_COMMAND_HPP_
#define DYNTRACE_DYNTRACED_COMMAND_HPP_

#include <dyntrace/comm/local.hpp>

namespace dyntrace::d
{
    class command_connection : public dyntrace::comm::local::command_connection
    {
    public:
        using dyntrace::comm::local::command_connection::command_connection;
    protected:
        std::optional<dyntrace::proto::response> on_request(uint64_t seq, const dyntrace::proto::command::request& req) override;
    private:
        std::optional<dyntrace::proto::response> on_request_to_process(uint64_t seq, const dyntrace::proto::command::process_request& req);
    };
}

#endif