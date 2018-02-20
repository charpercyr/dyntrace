#ifndef DYNTRACE_COMM_LOCAL_HPP_
#define DYNTRACE_COMM_LOCAL_HPP_

#include "message.hpp"

#include <command.pb.h>
#include <process.pb.h>

namespace dyntrace::comm::local
{
    using protocol = boost::asio::local::stream_protocol;
    using server = dyntrace::comm::server<protocol>;
    using acceptor = server::acceptor;
    using endpoint = server::endpoint;
    using socket = server::socket;

    template<typename Body>
    using message_connection = dyntrace::comm::message_connection<protocol, Body>;
    using command_connection = message_connection<dyntrace::proto::command::command_message>;
    using process_connection = message_connection<dyntrace::proto::process::process_message>;

    template<typename Conn, typename...Args>
    auto make_connection_factory(Args&&...args)
    {
        return dyntrace::comm::make_connection_factory<protocol, Conn>(std::forward<Args>(args)...);
    }
}

#endif