#ifndef DYNTRACE_COMM_LOCAL_HPP_
#define DYNTRACE_COMM_LOCAL_HPP_

#include "server.hpp"

namespace dyntrace::comm::local
{
    using protocol = boost::asio::local::stream_protocol;
    using server = dyntrace::comm::server<protocol>;
    using acceptor = server::acceptor;
    using endpoint = server::endpoint;
    using iostream = server::iostream;
    using socket = server::socket;
}

#endif