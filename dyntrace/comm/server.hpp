#ifndef DYNTRACE_COMM_SERVER_HPP_
#define DYNTRACE_COMM_SERVER_HPP_

#include <boost/asio.hpp>

#include <iostream>
#include <memory>
#include <unordered_map>

namespace dyntrace::comm
{
    template<typename Protocol>
    class server;

    template<typename Protocol>
    class connection_base
    {
    public:
        using protocol_type = Protocol;
        using socket_type = typename protocol_type::socket;
        using server_type = server<protocol_type>;

        connection_base(server_type* srv, socket_type sock)
            : _srv{srv}, _sock{std::move(sock)} {}
        virtual ~connection_base() = default;

        void close();

    protected:
        socket_type& get_socket()
        {
            return _sock;
        }
        server_type& get_server()
        {
            return *_srv;
        }
    private:
        server_type* _srv;
        socket_type _sock;
    };

    template<typename Protocol>
    class server
    {
    public:
        using this_type = server<Protocol>;
        using protocol_type = Protocol;
        using acceptor = typename protocol_type::acceptor;
        using endpoint = typename protocol_type::endpoint;
        using socket = typename protocol_type::socket;
        using connection_type = connection_base<Protocol>;
        using connection_factory = std::function<std::unique_ptr<connection_type>(this_type*, socket)>;

        server(boost::asio::io_context& ctx, const endpoint& e, connection_factory factory)
            : _acc{ctx, e}, _factory{std::move(factory)} {}

        void start()
        {
            _acc.async_accept(
                [this](const boost::system::error_code& err, socket sock)
                {
                    std::cout << "New connection" << std::endl;
                    auto c = _factory(this, std::move(sock));
                    if(c)
                        _conns.insert(std::make_pair(c.get(), std::move(c)));
                    start();
                }
            );
        }

        void stop()
        {
            _acc.close();
        }

        void close(connection_type* conn)
        {
            std::cout << "Close connection" << std::endl;
            _conns.erase(conn);
        }

    private:
        std::unordered_map<connection_type*, std::unique_ptr<connection_type>> _conns;
        connection_factory _factory;
        acceptor _acc;
    };

    template<typename Protocol>
    void connection_base<Protocol>::close()
    {
        _srv->close(this);
    }

    template<typename Protocol, typename Conn>
    std::unique_ptr<connection_base<Protocol>> connection_factory(server<Protocol>* srv, typename server<Protocol>::socket sock)
    {
        return std::make_unique<Conn>(srv, std::move(sock));
    };
}

#endif