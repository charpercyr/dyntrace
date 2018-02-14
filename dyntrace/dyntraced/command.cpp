#include "command.hpp"

using namespace dyntrace::d;

std::optional<dyntrace::proto::response> command_connection::on_request(uint64_t seq, const dyntrace::proto::command::request& req)
{
    if(req.has_to_proc())
    {
        return on_request_to_process(seq, req.to_proc());
    }
    else if(req.has_list_proc())
    {
        BOOST_LOG_TRIVIAL(info) << "Request: List proc";
        return dyntrace::proto::response{};
    }
    else
    {
        send_bad_message(seq);
        return {};
    }
}

std::optional<dyntrace::proto::response> command_connection::on_request_to_process(uint64_t seq, const dyntrace::proto::command::process_request& req)
{
    BOOST_LOG_TRIVIAL(info) << "Request: to process " << req.pid();
    return dyntrace::proto::response{};
}