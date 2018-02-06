#include "process.hpp"

using namespace dyntrace::comm;

namespace dyntrace::comm
{
    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const process_body& proc) noexcept
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
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, process_body& proc)
    {
        if(!root.IsObject())
            throw bad_message_error{};
        if(!root.GetObject().HasMember("type"))
            throw bad_message_error{};
        if(!root.GetObject()["type"].IsString())
            throw bad_message_error{};

        if(root.GetObject()["type"].GetString() == "hello")
        {
            proc = hello_body{};
            unserialize(doc, root, std::get<hello_body>(proc));
        }
        else if(root.GetObject()["type"].GetString() == "bye")
        {
            proc = bye_body{};
            unserialize(doc, root, std::get<bye_body>(proc));
        }
    }

    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const hello_body& proc) noexcept
    {
        root.GetObject().AddMember(rapidjson::StringRef("pid"), proc.pid, doc.GetAllocator());
    }
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, hello_body& proc)
    {
        if(!root.GetObject().HasMember("pid"))
            throw bad_message_error{};
        if(!root.GetObject()["pid"].IsInt())
            throw bad_message_error{};

        proc.pid = root.GetObject()["pid"].GetInt();
    }

    void serialize(rapidjson::Document& doc, rapidjson::Value& root, const bye_body& proc) noexcept
    {
        // Nothing
    }
    void unserialize(rapidjson::Document& doc, const rapidjson::Value& root, bye_body& proc)
    {
        // Nothing
    }
}