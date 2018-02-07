#ifndef DYNTRACE_COMM_MESSAGE_HPP_
#define DYNTRACE_COMM_MESSAGE_HPP_

#include <cstdint>
#include <exception>

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
    class message_handler
    {
    public:
        using this_type = message_handler<Protocol, Body>;
        using protocol_type = Protocol;
        using socket = typename protocol_type::socket;
        using message_type = message<Body>;
        using connection_manager_type = connection_manager<protocol_type, this_type>;

        message_handler(connection_manager_type*, socket sock)
            : _sock{std::move(sock)}
        {
            handle();
        }

        void send(const message_type& msg)
        {
            rapidjson::Document doc;
            serialize(doc, doc, msg);
            rapidjson::StringBuffer buf;
            rapidjson::Writer writer{buf};
            doc.Accept(writer);
            _sock.send(boost::asio::buffer(buf.GetString(), buf.GetSize()));
        }

    protected:
        virtual void on_message(const message_type& msg) = 0;

    private:

        void handle()
        {
            _sock.async_wait(
                socket::wait_read,
                [this](boost::system::error_code& err)
                {
                    if(!err)
                    {
                        union
                        {
                            uint8_t buf[4];
                            uint32_t val;
                        } msg_size;
                        _sock.receive(boost::asio::buffer(msg_size.buf));
                        std::vector<char> data(msg_size.val);
                        size_t received = 0;
                        while(received < msg_size.val)
                        {
                            received += _sock.receive(boost::asio::buffer(data.data() + received, msg_size.val - received));
                        }
                        rapidjson::Document doc;
                        doc.Parse(data.data(), data.size());
                        message_type msg;
                        unserialize(doc, doc, msg);
                        on_message(msg);
                        handle();
                    }
                }
            );
        }

        socket _sock;
    };
}

#endif