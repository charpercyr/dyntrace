#ifndef DYNTRACE_COMM_LOCAL_HPP_
#define DYNTRACE_COMM_LOCAL_HPP_

#include "command.hpp"
#include "process.hpp"

namespace dyntrace::comm::local
{
    using protocol = boost::asio::local::stream_protocol;
    using server = dyntrace::comm::server<protocol>;
    using acceptor = server::acceptor;
    using endpoint = server::endpoint;
    using socket = server::socket;

    using command_connection = dyntrace::comm::command_connection<protocol>;
    using process_connection = dyntrace::comm::process_connection<protocol>;

    template<typename Conn, typename...Args>
    auto make_connection_factory(Args&&...args)
    {
        return dyntrace::comm::make_connection_factory<protocol, Conn>(std::forward<Args>(args)...);
    }
}

#endif