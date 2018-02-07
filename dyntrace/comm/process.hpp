#ifndef DYNTRACE_COMM_PROCESS_HPP_
#define DYNTRACE_COMM_PROCESS_HPP_

#include "message.hpp"

#include <string>
#include <variant>

namespace dyntrace::comm
{
    struct hello_body
    {
        pid_t pid;
    };

    struct bye_body
    {
        // Nothing
    };

    using process_body = std::variant<hello_body, bye_body>;
    using process_message = message<process_body>;

    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const process_body& proc) noexcept;
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, process_body& proc);
    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const hello_body& proc) noexcept;
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, hello_body& proc);
    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const bye_body& proc) noexcept;
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, bye_body& proc);

    inline void serialize(rapidjson::Document& doc, rapidjson::Value& root, const process_body& proc) noexcept
    {
        root.SetObject();
        if(std::holds_alternative<hello_body>(proc))
        {
            root.GetObject().AddMember(rapidjson::StringRef("type"), rapidjson::StringRef("hello"), doc.GetAllocator());
            serialize(doc, root, std::get<hello_body>(proc));
        }
        else if(std::holds_alternative<bye_body>(proc))
        {
            root.GetObject().AddMember(rapidjson::StringRef("type"), rapidjson::StringRef("bye"), doc.GetAllocator());
            serialize(doc, root, std::get<bye_body>(proc));
        }
    }
    inline void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, process_body& proc)
    {
        using namespace std::string_literals;
        if(!root.IsObject())
            throw bad_message_error{};
        if(!root.GetObject().HasMember("type"))
            throw bad_message_error{};
        if(!root.GetObject()["type"].IsString())
            throw bad_message_error{};

        if(root.GetObject()["type"].GetString() == "hello"s)
        {
            proc = hello_body{};
            unserialize(doc, root, std::get<hello_body>(proc));
        }
        else if(root.GetObject()["type"].GetString() == "bye"s)
        {
            proc = bye_body{};
            unserialize(doc, root, std::get<bye_body>(proc));
        }
        else
            throw bad_message_error{};
    }

    inline void serialize(rapidjson::Document& doc, rapidjson::Value& root, const hello_body& proc) noexcept
    {
        root.GetObject().AddMember(rapidjson::StringRef("pid"), proc.pid, doc.GetAllocator());
    }
    inline void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, hello_body& proc)
    {
        if(!root.GetObject().HasMember("pid"))
            throw bad_message_error{};
        if(!root.GetObject()["pid"].IsInt())
            throw bad_message_error{};

        proc.pid = root.GetObject()["pid"].GetInt();
    }

    inline void serialize(rapidjson::Document& doc, rapidjson::Value& root, const bye_body& proc) noexcept
    {
        // Nothing
    }
    inline void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, bye_body& proc)
    {
        // Nothing
    }

    template<typename Protocol>
    class process_connection : public message_connection<Protocol, process_body>
    {
    public:

        using message_connection<Protocol, process_body>::message_connection;

    protected:

        virtual void on_hello(size_t seq, const hello_body& hello) = 0;
        virtual void on_bye(size_t seq, const bye_body& bye) = 0;

        void on_message(const message<process_body>& msg) final
        {
            if(std::holds_alternative<hello_body>(msg.body))
                on_hello(msg.seq, std::get<hello_body>(msg.body));
            else if(std::holds_alternative<bye_body>(msg.body))
                on_bye(msg.seq, std::get<bye_body>(msg.body));
        }
    private:
    };
}

#endif