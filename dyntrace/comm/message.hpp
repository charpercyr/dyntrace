#ifndef DYNTRACE_COMM_MESSAGE_HPP_
#define DYNTRACE_COMM_MESSAGE_HPP_

#include <cstdint>
#include <exception>

#include <rapidjson/document.h>

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
}

#endif