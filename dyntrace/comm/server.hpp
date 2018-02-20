#ifndef DYNTRACE_COMM_SERVER_HPP_
#define DYNTRACE_COMM_SERVER_HPP_

#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>

#include <unordered_map>

#include <util/refcnt.hpp>

namespace dyntrace::comm
{
    template<typename Protocol>
    class server;

    template<typename Protocol>
    class connection_base : public dyntrace::safe_refcnt_base<connection_base<Protocol>>
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
        using connection_factory = std::function<dyntrace::refcnt_ptr<connection_type>(this_type*, socket)>;

        server(boost::asio::io_context& ctx, const endpoint& e, connection_factory factory)
            : _factory{std::move(factory)}, _acc{ctx, e} {}

        void start()
        {
            _acc.async_accept(
                [this](const boost::system::error_code& err, socket sock)
                {
                    BOOST_LOG_TRIVIAL(info) << "[" << _acc.local_endpoint() << "] New connection";
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
            BOOST_LOG_TRIVIAL(info) << "[" << _acc.local_endpoint() << "] Close connection";
            _conns.erase(conn);
        }

    private:
        std::unordered_map<connection_type*, dyntrace::refcnt_ptr<connection_type>> _conns;
        connection_factory _factory;
        acceptor _acc;
    };

    template<typename Protocol>
    void connection_base<Protocol>::close()
    {
        _sock.close();
        _srv->close(this);
    }

    template<typename Protocol, typename Conn, typename...Args>
    auto make_connection_factory(Args&&...args)
    {
        return
            [t = std::make_tuple(std::forward<Args>(args)...)]
            (server<Protocol>* srv, typename server<Protocol>::socket sock)
        {
            static constexpr auto make_refcnt = [](auto&&...a) -> dyntrace::refcnt_ptr<connection_base<Protocol>>
            {
                return dyntrace::make_refcnt<Conn>(std::forward<decltype(a)>(a)...);
            };
            return std::apply(make_refcnt, std::tuple_cat(std::make_tuple(srv, std::move(sock)), t));
        };
    };
}

#endif