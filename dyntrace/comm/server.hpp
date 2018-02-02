#ifndef DYNTRACE_COMM_SERVER_HPP_
#define DYNTRACE_COMM_SERVER_HPP_

#include "handler.hpp"

#include <boost/asio.hpp>

namespace dyntrace::comm
{
    template<typename Proto>
    class server
    {
    public:
        using protocol = Proto;
        using acceptor = typename protocol::acceptor;
        using endpoint = typename protocol::endpoint;
        using socket = typename protocol::socket;
        using handler = dyntrace::comm::handler<protocol>;
        using connection_handler = dyntrace::comm::connection_handler<protocol>;

        explicit server(boost::asio::io_context& ctx, handler& h, const endpoint& e)
            : _acc{ctx, e}, _h{h}
        {
            do_accept();
        }

        void stop()
        {
            _acc.close();
        }

    private:

        void do_accept()
        {
            _acc.async_accept([this](const boost::system::error_code& err, socket sock)
            {
                _h.accept(std::move(sock));
                do_accept();
            });
        }

        acceptor _acc;
        handler& _h;
    };
}

#endif