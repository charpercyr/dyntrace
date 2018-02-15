#ifndef DYNTRACE_COMM_PROCESS_HPP_
#define DYNTRACE_COMM_PROCESS_HPP_

#include "message.hpp"

#include <string>
#include <variant>

#include <common.pb.h>
#include <process.pb.h>

namespace dyntrace::comm
{
    template<typename Protocol>
    class process_connection : public message_connection<Protocol, dyntrace::proto::process::process_message>
    {
        using message_type = dyntrace::proto::process::process_message;
        using hello_type = dyntrace::proto::process::hello;
        using bye_type = dyntrace::proto::process::bye;
        using request_type = dyntrace::proto::process::request;
        using response_type = dyntrace::proto::response;
        using base_type = message_connection<Protocol, message_type>;
    public:
        using base_type::base_type;

    protected:

        virtual void on_hello(uint64_t seq, const hello_type& hello) = 0;
        virtual void on_bye(uint64_t seq, const bye_type& bye) = 0;
        virtual response_type on_request(uint64_t seq, const request_type& request) = 0;

        void on_message(const message_type& msg) final
        {
            try
            {
                if (msg.has_hello())
                {
                    on_hello(msg.seq(), msg.hello());
                }
                else if (msg.has_bye())
                {
                    on_bye(msg.seq(), msg.bye());
                }
                else if (msg.has_req())
                {
                    auto resp = on_request(msg.seq(), msg.req());
                    resp.set_req_seq(msg.seq());
                    message_type resp_msg{};
                    resp_msg.set_seq(_next_seq++);
                    resp_msg.set_allocated_resp(new response_type{std::move(resp)});
                    base_type::send(resp_msg);
                }
                else
                    throw bad_message_error{};
            }
            catch(const std::exception& e)
            {
                on_error(msg.seq(), &e);
            }
            catch(...)
            {
                on_error(msg.seq(), nullptr);
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