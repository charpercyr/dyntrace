#ifndef DYNTRACE_COMM_MESSAGE_HPP_
#define DYNTRACE_COMM_MESSAGE_HPP_

#include <cstdint>
#include <limits>
#include <stdexcept>

#include "server.hpp"

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
            start_receive();
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
        virtual void on_error(uint64_t seq, const std::exception* e)
        {
            if(e)
                throw *e;
            else
                throw std::runtime_error{"unknown exception"};
        }

    private:
        std::array<char, 4096> _buffer;

        void start_receive()
        {
            this_type::get_socket().async_receive(
                boost::asio::buffer(_buffer),
                [this](const boost::system::error_code& err, size_t received)
                {
                    if(err)
                        this_type::close();
                    else
                    {
                        size_t received_count = 0;
                        while(received)
                        {
                            ++received_count;
                            auto msg_size = *reinterpret_cast<uint32_t*>(_buffer.data());
                            received -= sizeof(uint32_t);
                            std::vector<char> data(msg_size);
                            std::copy(_buffer.begin() + sizeof(uint32_t), _buffer.begin() + msg_size + sizeof(uint32_t),
                                      data.begin());

                            if (received >= msg_size)
                            {
                                finish_receive(std::move(data));
                                if(received_count == 1)
                                    start_receive();

                            }
                            else if(received)
                                continue_receive(std::move(data), received);
                            received -= msg_size;
                        }
                    }
                }
            );
        }

        void continue_receive(std::vector<char> data, size_t total_received)
        {
            this_type::get_socket().async_receive(
                boost::asio::buffer(_buffer),
                [this, data = std::move(data), total_received](const boost::system::error_code& err, size_t received) mutable
                {
                    if(err)
                        this_type::close();
                    else
                    {
                        std::copy(_buffer.begin(), _buffer.begin() + received, data.begin() + total_received);
                        if(received >= data.size())
                        {
                            finish_receive(std::move(data));
                            start_receive();
                        }
                        else
                            continue_receive(std::move(data), total_received + received);
                    }
                }
            );
        }

        void finish_receive(std::vector<char> data)
        {
            message_type msg;
            msg.ParseFromArray(data.data(), data.size());
            try
            {
                on_message(msg);
            }
            catch(const std::exception& e)
            {
                on_error(msg.seq(), &e);
            }
            catch(...)
            {
                on_error(msg.seq(), nullptr);
            }
        }
    };
}

#endif