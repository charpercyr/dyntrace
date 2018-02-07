#ifndef DYNTRACE_COMM_SERVER_HPP_
#define DYNTRACE_COMM_SERVER_HPP_

#include <boost/asio.hpp>

#include <memory>
#include <unordered_map>

namespace dyntrace::comm
{
    template<typename Protocol>
    struct connection_manager_base
    {
        virtual ~connection_manager_base() = default;
        virtual void new_connection(typename Protocol::socket sock) = 0;
    };
    template<typename Protocol, typename Handler>
    class connection_manager : public connection_manager_base<Protocol>
    {
    public:
        using protocol_type = Protocol;
        using iostream = typename protocol_type::iostream;
        using socket = typename protocol_type::socket;
        using handler_type = Handler;

        void new_connection(socket sock) override
        {
            auto h = std::make_unique<handler_type>(this, std::move(sock));
            _handlers.insert(std::make_pair(h.get(), std::move(h)));
        }

        void close(handler_type* h)
        {
            auto it = _handlers.find(h);
            if(it != _handlers.end())
                _handlers.erase(it);
        }

    private:
        std::unordered_map<handler_type*, std::unique_ptr<handler_type>> _handlers;
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
        using connection_manager_type = connection_manager_base<protocol_type>;

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