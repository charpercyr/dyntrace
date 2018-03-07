#include "command.hpp"
#include "config.hpp"

#include "dyntrace/inject/injector.hpp"
#include "dyntrace/util/path.hpp"
#include "dyntrace/util/error.hpp"

#include <experimental/filesystem>

using namespace dyntrace::d;
namespace fs = std::experimental::filesystem;

void command_connection::on_message(const message_type& msg)
{
    if(msg.has_req())
    {
        message_type resp;
        resp.set_seq(next_seq());
        resp.mutable_resp()->set_req_seq(msg.seq());
        if(msg.req().has_list_proc())
        {
            resp.mutable_resp()->mutable_ok()->mutable_procs();
            for(auto pid : _reg->all_processes())
            {
                auto proc = resp.mutable_resp()->mutable_ok()->mutable_procs()->add_procs();
                proc->set_pid(pid);
                for(auto&& a : dyntrace::read_cmdline(pid))
                    proc->add_command_line(std::forward<decltype(a)>(a));
            }
            send(resp);
        }
        else if(msg.req().has_att())
        {
            pid_t pid;
            if(!msg.req().att().name().empty())
                pid = dyntrace::find_process(msg.req().att().name());
            else
                pid = msg.req().att().pid();
            dyntrace::inject::injector inj{pid};
            inj.inject(config::agent_library);
            resp.mutable_resp()->mutable_ok();
            send(resp);
        }
        else
            on_process_message(msg.seq(), msg.req().to_proc());
    }
    else
        on_bad_message(msg.seq());
}

void command_connection::on_error(uint64_t seq, const std::exception* e)
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

void command_connection::on_process_message(uint64_t seq, const proto::command::process_request& msg)
{
    message_type resp;
    resp.set_seq(next_seq());

    pid_t pid = -1;
    if(msg.pid() != 0)
    {
        pid = msg.pid();
    }
    else
    {
        try
        {
            pid = dyntrace::find_process(msg.name());
        }
        catch(dyntrace::dyntrace_error&)
        {
            // Nothing, next 'if' will do the error check
        }
    }

    if(auto proc = _reg->get(pid))
    {
        proc->send(msg.req(), [this, resp = std::move(resp), seq](const proto::response& proc_resp) mutable
        {
            resp.mutable_resp()->CopyFrom(proc_resp);
            resp.mutable_resp()->set_req_seq(seq);
            send(resp);
        });
    }
    else
    {
        resp.mutable_resp()->set_req_seq(seq);
        resp.mutable_resp()->mutable_err()->set_type("invalid_process");
        resp.mutable_resp()->mutable_err()->set_msg("process " + (msg.pid() ? std::to_string(msg.pid()) : msg.name()) + " does not exist");
        send(resp);
    }
}