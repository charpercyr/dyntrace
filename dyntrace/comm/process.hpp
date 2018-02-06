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
}

#endif