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

    struct list_process {};
    struct add_tracepoint
    {
        int pid;
        std::variant<uint64_t, std::string> location;
        std::string tracer;
        std::optional<std::string> name;
    };
    struct remove_tracepoint
    {
        int pid;
        std::string name;
    };
    struct list_tracepoint
    {
        int pid;
    };
    using request_body = std::variant<
        list_process,
        add_tracepoint,
        remove_tracepoint,
        list_tracepoint
    >;
    struct tracepoint_created
    {
        std::string name;
    };
    struct response_ok
    {
        std::variant<std::monostate, tracepoint_created> sub;
    };
    struct response_error
    {
        std::string err;
    };
    using response_sub = std::variant<response_error, response_ok>;
    struct response_body
    {
        uint64_t seq;
        response_sub response;
    };

    using process_body = std::variant<hello_body, bye_body, request_body, response_body>;
    using process_message = message<process_body>;

    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const process_body& proc) noexcept;
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, process_body& proc);
    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const hello_body& proc) noexcept;
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, hello_body& proc);
    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const bye_body& proc) noexcept;
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, bye_body& proc);

    inline void serialize(rapidjson::Document& doc, rapidjson::Value& root, const request_body& proc) noexcept;
    inline void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, request_body& proc);
    inline void serialize(rapidjson::Document& doc, rapidjson::Value& root, const response_body& proc) noexcept;
    inline void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, response_body& proc);

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
        else if(std::holds_alternative<request_body>(proc))
        {
            root.GetObject().AddMember(rapidjson::StringRef("type"), rapidjson::StringRef("request"), doc.GetAllocator());
            serialize(doc, root, std::get<request_body>(proc));
        }
        else if(std::holds_alternative<response_body>(proc))
        {
            root.GetObject().AddMember(rapidjson::StringRef("type"), rapidjson::StringRef("response"), doc.GetAllocator());
            serialize(doc, root, std::get<response_body>(proc));
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
        else if(root.GetObject()["type"].GetString() == "request"s)
        {
            proc = request_body{};
            unserialize(doc, root, std::get<request_body>(proc));
        }
        else if(root.GetObject()["type"].GetString() == "response"s)
        {
            proc = response_body{};
            unserialize(doc, root, std::get<response_body>(proc));
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

    inline void serialize(rapidjson::Document& doc, rapidjson::Value& root, const request_body& proc) noexcept
    {
        if (std::holds_alternative<list_process>(proc))
        {
            root.GetObject().AddMember(
                "request",
                "list_process",
                doc.GetAllocator()
            );
        }
        else if (std::holds_alternative<add_tracepoint>(proc))
        {
            const auto& atp = std::get<add_tracepoint>(proc);
            root.GetObject().AddMember(
                "request",
                "add_tracepoint",
                doc.GetAllocator()
            );
            root.GetObject().AddMember(
                "pid",
                atp.pid,
                doc.GetAllocator()
            );
            if(std::holds_alternative<uint64_t>(atp.location))
            {
                root.GetObject().AddMember(
                    "location",
                    std::get<uint64_t>(atp.location),
                    doc.GetAllocator()
                );
            }
            else
            {
                root.GetObject().AddMember(
                    "location",
                    rapidjson::StringRef(std::get<std::string>(atp.location).c_str()),
                    doc.GetAllocator()
                );
            }
            root.GetObject().AddMember(
                "tracer",
                rapidjson::StringRef(atp.tracer.c_str()),
                doc.GetAllocator()
            );
            if(atp.name)
            {
                root.GetObject().AddMember(
                    "name",
                    rapidjson::StringRef(atp.name.value().c_str()),
                    doc.GetAllocator()
                );
            }
        }
        else if(std::holds_alternative<remove_tracepoint>(proc))
        {
            const auto& rtp = std::get<remove_tracepoint>(proc);
            root.GetObject().AddMember(
                "request",
                "remove_tracepoint",
                doc.GetAllocator()
            );
            root.GetObject().AddMember(
                "pid",
                rtp.pid,
                doc.GetAllocator()
            );
            root.GetObject().AddMember(
                "name",
                rapidjson::StringRef(rtp.name.c_str()),
                doc.GetAllocator()
            );
        }
        else if(std::holds_alternative<list_tracepoint>(proc))
        {
            root.GetObject().AddMember(
                "request",
                "list_tracepoint",
                doc.GetAllocator()
            );
            root.GetObject().AddMember(
                "pid",
                std::get<list_tracepoint>(proc).pid,
                doc.GetAllocator()
            );
        }
    }
    inline void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, request_body& proc)
    {
        using namespace std::string_literals;

        if(!root.GetObject().HasMember("request"))
            throw bad_message_error{};
        if(!root.GetObject()["request"].IsString())
            throw bad_message_error{};
        if(root.GetObject()["request"].GetString() == "list_process"s)
            proc = list_process{};

        else if(root.GetObject()["request"].GetString() == "add_tracepoint"s)
        {
            proc = add_tracepoint{};
            auto& atp = std::get<add_tracepoint>(proc);

            if(!root.GetObject().HasMember("pid"))
                throw bad_message_error{};
            if(!root.GetObject()["pid"].IsInt())
                throw bad_message_error{};
            atp.pid = root.GetObject()["pid"].GetInt();

            if(!root.GetObject().HasMember("location"))
                throw bad_message_error{};
            if(root.GetObject()["location"].IsString())
                atp.location = std::string{root.GetObject()["location"].GetString()};
            else if(root.GetObject()["location"].IsUint64())
                atp.location = root.GetObject()["location"].GetUint64();
            else
                throw bad_message_error{};

            if(!root.GetObject().HasMember("tracer"))
                throw bad_message_error{};
            if(!root.GetObject()["tracer"].IsString())
                throw bad_message_error{};
            atp.tracer = root.GetObject()["tracer"].GetString();

            if(root.GetObject().HasMember("name"))
            {
                if(!root.GetObject()["name"].IsString())
                    throw bad_message_error{};
                atp.name = root.GetObject()["name"].GetString();
            }
        }
        else if(root.GetObject()["request"].GetString() == "remove_tracepoint"s)
        {
            proc = remove_tracepoint{};
            auto& rtp = std::get<remove_tracepoint>(proc);

            if(!root.GetObject().HasMember("pid"))
                throw bad_message_error{};
            if(!root.GetObject()["pid"].IsInt())
                throw bad_message_error{};
            rtp.pid = root.GetObject()["pid"].GetInt();

            if(!root.GetObject().HasMember("name"))
                throw bad_message_error{};
            if(!root.GetObject()["name"].IsString())
                throw bad_message_error{};
            rtp.name = root.GetObject()["name"].GetString();
        }
        else if(root.GetObject()["request"].GetString() == "list_tracepoint"s)
        {
            proc = list_tracepoint{};

            if(!root.GetObject().HasMember("pid"))
                throw bad_message_error{};
            if(!root.GetObject()["pid"].IsInt())
                throw bad_message_error{};
            std::get<list_tracepoint>(proc).pid = root.GetObject()["pid"].GetInt();
        }
        else
            throw bad_message_error{};
    }

    inline void serialize(rapidjson::Document& doc, rapidjson::Value& root, const response_body& proc) noexcept
    {
        root.GetObject().AddMember(
            "seq",
            proc.seq,
            doc.GetAllocator()
        );
        if(std::holds_alternative<response_ok>(proc.response))
        {
            const auto& ok = std::get<response_ok>(proc.response);
            root.GetObject().AddMember(
                "response",
                "ok",
                doc.GetAllocator()
            );
            if(std::holds_alternative<tracepoint_created>(ok.sub))
            {
                root.GetObject().AddMember(
                    "sub",
                    "tracepoint_created",
                    doc.GetAllocator()
                );
                root.GetObject().AddMember(
                    "name",
                    rapidjson::StringRef(std::get<tracepoint_created>(ok.sub).name.c_str()),
                    doc.GetAllocator()
                );
            }
        }
        else if(std::holds_alternative<response_error>(proc.response))
        {
            const auto& err = std::get<response_error>(proc.response);
            root.GetObject().AddMember(
                "response",
                "err",
                doc.GetAllocator()
            );
            root.GetObject().AddMember(
                "err",
                rapidjson::StringRef(err.err.c_str()),
                doc.GetAllocator()
            );
        }
    }
    inline void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, response_body& proc)
    {
        using namespace std::string_literals;

        if(!root.GetObject().HasMember("response"))
            throw bad_message_error{};
        if(!root.GetObject()["response"].IsString())
            throw bad_message_error{};

        if(!root.GetObject().HasMember("seq"))
            throw bad_message_error{};
        if(!root.GetObject()["seq"].IsUint64())
            throw bad_message_error{};
        proc.seq = root.GetObject()["seq"].GetUint64();

        if(root.GetObject()["response"].GetString() == "ok"s)
        {
            proc.response = response_ok{};
            auto& ok = std::get<response_ok>(proc.response);
            if(root.GetObject().HasMember("sub"))
            {
                if(!root.GetObject()["sub"].IsString())
                    throw bad_message_error{};
                if(root.GetObject()["sub"].GetString() == "tracepoint_created"s)
                {
                    ok.sub = tracepoint_created{};
                    if(!root.GetObject().HasMember("name"))
                        throw bad_message_error{};
                    if(!root.GetObject()["name"].IsString())
                        throw bad_message_error{};
                    std::get<tracepoint_created>(ok.sub).name = root.GetObject()["name"].GetString();
                }
            }
        }
        else if(root.GetObject()["response"].GetString() == "err"s)
        {
            proc.response = response_error{};
            auto& err = std::get<response_error>(proc.response);
            if(!root.GetObject().HasMember("err"))
                throw bad_message_error{};
            if(!root.GetObject()["err"].IsString())
                throw bad_message_error{};
            err.err = root.GetObject()["err"].GetString();
        }
    }

    template<typename Protocol>
    class process_connection : public message_connection<Protocol, process_body>
    {
        using base_type = message_connection<Protocol, process_body>;
    public:

        using base_type::base_type;

    protected:

        virtual void on_hello(uint64_t seq, const hello_body& hello) = 0;
        virtual void on_bye(uint64_t seq, const bye_body& bye) = 0;
        virtual response_sub on_request(size_t seq, const request_body& req) = 0;

        void on_message(const message<process_body>& msg) final
        {
            using namespace std::string_literals;

            if(std::holds_alternative<hello_body>(msg.body))
                on_hello(msg.seq, std::get<hello_body>(msg.body));
            else if(std::holds_alternative<bye_body>(msg.body))
                on_bye(msg.seq, std::get<bye_body>(msg.body));
            else if(std::holds_alternative<request_body>(msg.body))
            {
                auto rep = on_request(msg.seq, std::get<request_body>(msg.body));
                message<process_body> rep_msg{};
                rep_msg.seq = _next_seq++;
                rep_msg.body = response_body{.seq = msg.seq, .response = rep};
                base_type::send(rep_msg);
            }
        }

        void on_error(uint64_t seq, const std::exception* e) final
        {
            using namespace std::string_literals;
            message<process_body> err_msg{};
            err_msg.seq = _next_seq++;
            response_sub sub;
            if(dynamic_cast<const bad_message_error*>(e))
            {
                sub = response_error{"bad_message"};
            }
            else if(e)
            {
                sub = response_error{"internal_error: "s + e->what()};
            }
            else
            {
                sub = response_error{"internal_error: unknown"};
            }
            err_msg.body = response_body{.seq = seq, .response = sub};
            base_type::send(err_msg);
        }
    private:
        uint64_t _next_seq{0};
    };
}

#endif