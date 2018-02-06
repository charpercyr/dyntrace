#ifndef DYNTRACE_COMM_SERVER_HPP_
#define DYNTRACE_COMM_SERVER_HPP_

#include <boost/asio.hpp>

namespace dyntrace::comm
{

    template<typename Protocol>
    class handler
    {
    public:

        virtual ~handler() = default;

    private:
    };

    template<typename Protocol>
    class connection_manager
    {
    public:
        using protocol_type = Protocol;
        using iostream = typename protocol_type::iostream;
        using socket = typename protocol_type::socket;
        using handler_type = handler<protocol_type>;

        virtual ~connection_manager() = default;

        void new_connection(socket sock)
        {

        }

    protected:
    };

    template<typename Protocol>
    class server
    {
    public:
        using protocol_type = Protocol;
        using acceptor = typename protocol_type::acceptor;
        using endpoint = typename protocol_type::endpoint;
        using iostream = typename protocol_type::iostream;
        using socket = typename protocol_type::socket;
        using connection_manager_type = connection_manager<protocol_type>;

        server(boost::asio::io_context& ctx, const endpoint& e, connection_manager_type& manager)
            : _acc{ctx, e}, _manager{manager} {}

        void start()
        {
            _acc.async_accept(
                [this](const boost::system::error_code& err, socket sock)
                {
                    _manager.new_connection(std::move(sock));
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
        connection_manager_type& _manager;
    };
}

#endif