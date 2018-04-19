#include "process.hpp"

using namespace dyntrace::d;

void process_connection::on_message(const message_type& msg)
{
    try
    {
        if (msg.has_resp())
        {
            auto pending = _pending.lock();
            auto it = pending->find(msg.resp().req_seq());
            if(it != pending->end())
            {
                it->second(msg.resp());
                pending->erase(it);
            }
            else
                BOOST_LOG_TRIVIAL(error) << "Unexpected message " << msg.DebugString();
        }
        else
            on_bad_message(msg.seq());
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

void process_connection::on_error(uint32_t seq, const std::exception* e)
{
    message_type msg{};
    msg.set_seq(next_seq());
    msg.mutable_resp()->set_req_seq(seq);
    if(dynamic_cast<const comm::bad_message_error*>(e))
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

void process_connection::send(const request_type& req, request_done_callback on_done)
{
    uint64_t seq = next_seq();
    {
        auto pending = _pending.lock();
        pending->insert(std::make_pair(seq, std::move(on_done)));
    }
    message_type msg;
    msg.set_seq(seq);
    msg.mutable_req()->CopyFrom(req);
    base_type::send(msg);
}