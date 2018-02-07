#ifndef DYNTRACE_COMM_PROCESS_HPP_
#define DYNTRACE_COMM_PROCESS_HPP_

#include <string>
#include <variant>

#include "message.hpp"

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

    template<typename Protocol>
    class process_handler : public message_handler<Protocol, process_body>
    {
    public:
        using message_handler<Protocol, process_body>::message_handler;

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