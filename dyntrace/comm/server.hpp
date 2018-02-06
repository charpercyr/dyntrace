#ifndef DYNTRACE_COMM_SERVER_HPP_
#define DYNTRACE_COMM_SERVER_HPP_

#include <boost/asio.hpp>

namespace dyntrace::comm
{
    template<typename Protocol>
    class server
    {
    public:
        using protocol_type = Protocol;
        using acceptor = typename protocol_type::acceptor;
        using endpoint = typename protocol_type::endpoint;
        using iostream = typename protocol_type::iostream;
        using socket = typename protocol_type::socket;

        server(boost::asio::io_context& ctx, const endpoint& e)
            : _acc{ctx, e} {}

        void start()
        {
            _acc.async_accept(
                [this](const boost::system::error_code& err, socket sock)
                {
                    sock.close();
                    start();
                }
            );
        }

        void stop()
        {
            _acc.close();
        }

    private:
        acceptor _acc;
    };
}

#endif