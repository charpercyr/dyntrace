#ifndef DYNTRACE_COMM_LOCAL_HPP_
#define DYNTRACE_COMM_LOCAL_HPP_

#include "process.hpp"

namespace dyntrace::comm::local
{
    using protocol = boost::asio::local::stream_protocol;
    using server = dyntrace::comm::server<protocol>;
    using acceptor = server::acceptor;
    using endpoint = server::endpoint;
    using socket = server::socket;

    using process_connection = dyntrace::comm::process_connection<protocol>;

    template<typename Conn>
    auto connection_factory(server* srv, socket sock)
    {
        return dyntrace::comm::connection_factory<protocol, Conn>(srv, std::move(sock));
    }
}

#endif