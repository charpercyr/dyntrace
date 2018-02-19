#ifndef DYNTRACE_COMM_PROCESS_HPP_
#define DYNTRACE_COMM_PROCESS_HPP_

#include "message.hpp"

#include <string>
#include <variant>

#include <common.pb.h>
#include <process.pb.h>

#include <util/locked.hpp>

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
        using request_done_callback = std::function<void(const response_type&)>;

        void send(const request_type& req, request_done_callback on_done)
        {
            uint64_t seq = _next_seq++;
            {
                auto pending = _pending.lock();
                pending->insert(std::make_pair(seq, std::move(on_done)));
            }
            message_type msg;
            msg.set_seq(seq);
            msg.mutable_req()->CopyFrom(req);
            base_type::send(msg);
        }

    protected:

        virtual void on_hello(uint64_t seq, const hello_type& hello) = 0;
        virtual void on_bye(uint64_t seq, const bye_type& bye) = 0;

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
                else if (msg.has_resp())
                {
                    auto pending = _pending.lock();
                    auto it = pending->find(msg.resp().req_seq());
                    if(it != pending->end())
                    {
                        it->second(msg.resp());
                        pending->erase(it);
                    }
                    else
                        BOOST_LOG_TRIVIAL(error) << "Response without request (seq=" << msg.seq() << ")";
                }
                else
                {
                    bad_message_error err;
                    on_error(msg.seq(), &err);
                }
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
        dyntrace::locked<std::unordered_map<uint64_t, request_done_callback>> _pending;
    };
}

#endif