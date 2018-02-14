#ifndef DYNTRACE_COMM_COMMAND_HPP_
#define DYNTRACE_COMM_COMMAND_HPP_

#include "message.hpp"

#include <command.pb.h>

namespace dyntrace::comm
{
    template<typename Protocol>
    class command_connection : public message_connection<Protocol, dyntrace::proto::command::command_message>
    {
        using message_type = dyntrace::proto::command::command_message;
        using request_type = dyntrace::proto::command::request;
        using response_type = dyntrace::proto::response;
        using base_type = message_connection<Protocol, message_type>;
    public:
        using base_type::base_type;

    protected:
        virtual std::optional<response_type> on_request(uint64_t seq, const request_type& req) = 0;

        void on_message(const message_type& msg) final
        {
            if(msg.has_req())
            {
                auto oresp = on_request(msg.seq(), msg.req());
                if(oresp)
                {
                    auto resp = oresp.value();
                    resp.set_req_seq(msg.seq());
                    message_type resp_msg{};
                    resp_msg.set_seq(_next_seq++);
                    resp_msg.set_allocated_resp(new response_type{std::move(resp)});
                    base_type::send(resp_msg);
                }
            }
            else
            {
                bad_message_error err{};
                on_error(msg.seq(), &err);
            }
        }
        void on_error(uint64_t seq, const std::exception* e) override
        {
            message_type msg{};
            msg.set_allocated_resp(new response_type);
            msg.mutable_resp()->set_req_seq(seq);
            msg.mutable_resp()->set_allocated_err(new dyntrace::proto::status_error);
            if(dynamic_cast<const bad_message_error*>(e))
            {
                msg.mutable_resp()->mutable_err()->set_type("bad_message");
                msg.mutable_resp()->mutable_err()->set_msg(e->what());
            }
            else if(e)
            {
                msg.mutable_resp()->mutable_err()->set_type("internal_error");
                msg.mutable_resp()->mutable_err()->set_msg(e->what());
            }
            else
            {
                msg.mutable_resp()->mutable_err()->set_type("internal_error");
            }
            base_type::send(msg);
        }
    private:
        uint64_t _next_seq{0};
    };
}

#endif