#ifndef DYNTRACE_COMM_LOCAL_HPP_
#define DYNTRACE_COMM_LOCAL_HPP_

#include "process.hpp"

namespace dyntrace::comm::local
{
    using protocol = boost::asio::local::stream_protocol;
    using server = dyntrace::comm::server<protocol>;
    using acceptor = server::acceptor;
    using endpoint = server::endpoint;
    using iostream = server::iostream;
    using socket = server::socket;

    template<typename Handler>
    using connection_manager = dyntrace::comm::connection_manager<protocol, Handler>;
    template<typename Body>
    using message_handler = dyntrace::comm::message_handler<protocol, Body>;
    using process_handler = dyntrace::comm::process_handler<protocol>;
}

#endif