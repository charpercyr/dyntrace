#include "command.hpp"

using namespace dyntrace::d;

dyntrace::proto::response command_connection::on_request(uint64_t seq, const dyntrace::proto::command::request& req)
{
    if(req.has_to_proc())
    {
        return on_request_to_process(seq, req.to_proc());
    }
    else if(req.has_list_proc())
    {
        BOOST_LOG_TRIVIAL(info) << "Request: List proc";
        dyntrace::proto::response resp;
        resp.mutable_ok();
        return resp;
    }
    else
    {
        throw dyntrace::comm::bad_message_error{};
    }
}

dyntrace::proto::response command_connection::on_request_to_process(uint64_t seq, const dyntrace::proto::command::process_request& req)
{
    BOOST_LOG_TRIVIAL(info) << "Request: to process " << req.pid();
    dyntrace::proto::response resp;
    resp.mutable_ok();
    return resp;
}