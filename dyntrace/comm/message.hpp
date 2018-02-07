#ifndef DYNTRACE_COMM_MESSAGE_HPP_
#define DYNTRACE_COMM_MESSAGE_HPP_

#include <cstdint>
#include <exception>
#include <iostream>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "server.hpp"

namespace dyntrace::comm
{
    class bad_message_error : public std::exception
    {
    public:

        bad_message_error()
            : _msg{"bad message"} {}
        explicit bad_message_error(const std::string msg)
            : _msg{"bad message: " + msg} {}

        const char* what() const noexcept override
        {
            return _msg.c_str();
        }

    private:
        std::string _msg;
    };

    template<typename Body>
    struct message
    {
        uint64_t seq;
        Body body;
    };

    template<typename Body>
    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const message<Body>& msg) noexcept
    {
        root.SetObject();
        root.GetObject().AddMember(rapidjson::StringRef("seq"), msg.seq, doc.GetAllocator());
        root.GetObject().AddMember(rapidjson::StringRef("body"), rapidjson::kNullType, doc.GetAllocator());
        serialize(doc, root.GetObject()["body"], msg.body);
    }

    template<typename Body>
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, message<Body>& msg)
    {
        if(!root.IsObject())
            throw bad_message_error{};
        if(!root.GetObject().HasMember("body"))
            throw bad_message_error{};
        msg.seq = root.GetObject()["seq"].GetUint64();
        unserialize(doc, root.GetObject()["body"], msg.body);
    }

    template<typename Protocol, typename Body>
    class message_connection : public connection_base<Protocol>
    {
    public:
        using base_type = connection_base<Protocol>;
        using this_type = message_connection<Protocol, Body>;
        using protocol_type = Protocol;
        using socket_type = typename protocol_type::socket;
        using message_type = message<Body>;
        using server_type = server<Protocol>;

        message_connection(server_type* srv, socket_type sock)
            : base_type{srv, std::move(sock)}
        {
            start_receive();
        }

        void send(const message_type& msg)
        {
            rapidjson::Document doc;
            serialize(doc, doc, msg);
            rapidjson::StringBuffer buf;
            rapidjson::Writer writer{buf};
            doc.Accept(writer);
            base_type::get_socket().send(boost::asio::buffer(buf.GetString(), buf.GetSize()));
        }

    protected:
        virtual void on_message(const message_type& msg) = 0;

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
                        auto msg_size = *reinterpret_cast<uint32_t*>(_buffer.data());
                        received -= sizeof(uint32_t);
                        std::vector<char> data(msg_size);
                        std::copy(_buffer.begin() + sizeof(uint32_t), _buffer.begin() + received + sizeof(uint32_t), data.begin());

                        if(received >= msg_size)
                            finish_receive(std::move(data));
                        else
                            continue_receive(std::move(data), received);
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
                            finish_receive(std::move(data));
                        else
                            continue_receive(std::move(data), total_received + received);
                    }
                }
            );
        }

        void finish_receive(std::vector<char> data)
        {
            rapidjson::Document doc;
            doc.Parse(data.data(), data.size());
            message_type msg{};
            unserialize(doc, doc, msg);
            on_message(msg);
            start_receive();
        }
    };
}

#endif