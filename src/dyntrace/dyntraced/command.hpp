#ifndef DYNTRACE_DYNTRACED_COMMAND_HPP_
#define DYNTRACE_DYNTRACED_COMMAND_HPP_

#include "local.hpp"
#include "process.hpp"

namespace dyntrace::d
{
    class command_connection final : public dyntrace::comm::local::command_connection
    {
    public:
        using message_type = proto::command::command_message;
        using request_type = proto::command::request;
        using response_type = proto::response;
        using base_type = dyntrace::comm::local::command_connection;

        using request_done_callback = std::function<void(const response_type&)>;
        command_connection(comm::local::server* srv, comm::local::socket sock, process_registry* reg)
            : dyntrace::comm::local::command_connection{srv, std::move(sock)}, _reg{reg} {}

    private:
        void on_message(const message_type& msg) override;
        void on_error(uint64_t seq, const std::exception* e) override;

        void on_process_message(uint64_t seq, const proto::command::process_request& msg);

        process_registry* _reg;
    };
}

#endif