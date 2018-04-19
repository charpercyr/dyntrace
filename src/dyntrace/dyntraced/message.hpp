#ifndef DYNTRACE_COMM_MESSAGE_HPP_
#define DYNTRACE_COMM_MESSAGE_HPP_

#include "server.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>

namespace dyntrace::comm
{
    struct bad_message_error : public std::runtime_error
    {
        bad_message_error() noexcept
            : std::runtime_error{"bad_message"} {}
        bad_message_error(const std::string& str) noexcept
            : std::runtime_error{"bad_message: " + str} {}
    };

    template<typename Protocol, typename Body>
    class message_connection : public connection_base<Protocol>
    {
    public:
        using base_type = connection_base<Protocol>;
        using this_type = message_connection<Protocol, Body>;
        using protocol_type = Protocol;
        using socket_type = typename protocol_type::socket;
        using server_type = server<Protocol>;
        using message_type = Body;

        message_connection(server_type* srv, socket_type sock)
            : base_type{srv, std::move(sock)}
        {
            do_receive();
        }

        void send(const message_type& msg)
        {
            std::string content;
            msg.SerializeToString(&content);
            std::vector<char> buf(content.size() + 4);
            *reinterpret_cast<uint32_t*>(buf.data()) = static_cast<uint32_t>(content.size());
            memcpy(buf.data() + 4, content.data(), content.size());
            base_type::get_socket().send(boost::asio::buffer(buf));
        }

    protected:
        virtual void on_message(const message_type& msg) = 0;
        virtual void on_error(uint32_t seq, const std::exception* e) = 0;

        void on_bad_message(uint32_t seq)
        {
            bad_message_error err;
            on_error(seq, &err);
        }

        uint32_t next_seq() const noexcept
        {
            return _next_seq.fetch_add(1, std::memory_order_relaxed);
        }

    private:
        mutable std::atomic<uint32_t> _next_seq{1};

        void do_receive()
        {
            using namespace boost::asio;
            auto to_recv = std::make_unique<uint32_t>();
            auto to_recv_addr = to_recv.get();
            async_read(
                this_type::get_socket(), buffer(to_recv_addr, sizeof(uint32_t)),
                [
                    to_recv = std::move(to_recv),
                    self = this_type::template refcnt_from_this<this_type>()
                ](const boost::system::error_code& err, size_t received)
                {
                    if(err || received != sizeof(uint32_t))
                    {
                        if(err != boost::asio::error::eof)
                            BOOST_LOG_TRIVIAL(error) << "error during size recv: " << err.message();
                        self->close();
                        return;
                    }
                    std::unique_ptr<uint8_t[]> data{new uint8_t[*to_recv]};
                    auto data_addr = data.get();
                    async_read(
                        self->get_socket(),
                        buffer(data_addr, *to_recv),
                        [data = std::move(data), self, to_recv = *to_recv](const boost::system::error_code& err, size_t received)
                        {
                            if(err || received != to_recv)
                            {
                                if(err != boost::asio::error::eof)
                                    BOOST_LOG_TRIVIAL(error) << "error during message recv: " << err.message();
                                self->close();
                                return;
                            }
                            message_type msg;
                            msg.ParseFromArray(data.get(), to_recv);
                            try
                            {
                                self->on_message(msg);
                            }
                            catch(const std::exception& e)
                            {
                                self->on_error(msg.seq(), &e);
                            }
                            catch(...)
                            {
                                self->on_error(msg.seq(), nullptr);
                            }
                            self->do_receive();
                        }
                    );
                }
            );
        }
    };
}

#endif