#ifndef DYNTRACE_COMM_LOCAL_HPP_
#define DYNTRACE_COMM_LOCAL_HPP_

#include "server.hpp"

namespace dyntrace::comm::local
{
    using protocol = boost::asio::local::stream_protocol;

    using acceptor = protocol::acceptor;
    using endpoint = protocol::endpoint;
    using socket = protocol::socket;

    using server = dyntrace::comm::server<protocol>;
    using handler = dyntrace::comm::handler<protocol>;
    using connection_handler = dyntrace::comm::connection_handler<protocol>;
    template<typename ConnectionHandler>
    using simple_handler = dyntrace::comm::simple_handler<protocol, ConnectionHandler>;
}

#endif