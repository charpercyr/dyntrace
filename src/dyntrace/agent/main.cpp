
#include "tracer.hpp"

#include "dyntrace/fasttp/fasttp.hpp"
#include "dyntrace/fasttp/error.hpp"

#include <config.hpp>
#include <process.pb.h>

#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>

#include <atomic>
#include <chrono>
#include <list>
#include <thread>
#include <variant>
#include <experimental/filesystem>

using namespace dyntrace;
using namespace dyntrace::agent;
namespace fs = std::experimental::filesystem;

struct bad_message_error : agent_error
{
    explicit bad_message_error(const std::string& msg = "") noexcept
        : agent_error{"bad_message_error", msg} {}
};

struct invalid_tracepoint_error : agent_error
{
    explicit invalid_tracepoint_error(const std::string& msg = "") noexcept
        : agent_error{"invalid_tracepoint_error", msg} {}
};

struct tracepoint_info
{
    dyntrace::fasttp::tracepoint tp;
    std::variant<std::string, uintptr_t> loc;
    std::string name;
    std::string tracer;
    bool entry_exit;
    std::vector<std::string> tracer_args;
};

class agent_main
{
public:
    agent_main()
        : _sock{_ctx}
    {
        std::thread th{&agent_main::run, this};
        th.detach();
    }

    void stop()
    {
        _done = true;
        _sock.close();
    }

private:

    void run()
    {
        using namespace boost::asio;
        using namespace std::chrono_literals;
        while(!_done.load(std::memory_order_relaxed))
        {
            try
            {
                static const auto sock_file =
                    fs::path{config::working_directory} / fs::path{config::process_socket_name};
                boost::system::error_code err;

                while (!_done.load(std::memory_order_relaxed)) // Try connecting
                {
                    _sock.connect(sock_file.c_str(), err);
                    if (!err)
                        break;
                    else // try again later
                        std::this_thread::sleep_for(5s);
                }

                while (!_done.load(std::memory_order_relaxed))
                {
                    uint32_t to_recv;
                    do_read(buffer(&to_recv, sizeof(to_recv)));
                    std::string data(to_recv, 0);
                    do_read(buffer(data));
                    proto::process::process_message msg;
                    msg.ParseFromString(data);
                    proto::process::process_message resp;
                    resp.set_seq(_next_seq++);
                    resp.mutable_resp()->CopyFrom(on_request(msg));
                    resp.SerializeToString(&data);
                    std::vector<char> buf(sizeof(uint32_t) + data.size());
                    *reinterpret_cast<uint32_t*>(buf.data()) = static_cast<uint32_t>(data.size());
                    memcpy(buf.data() + sizeof(uint32_t), data.data(), data.size());
                    write(_sock, buffer(buf));
                }
            }
            catch (boost::system::system_error& e)
            {
                if(e.code() != boost::asio::error::eof)
                    BOOST_LOG_TRIVIAL(error) << "Error during agent execution: " << e.what();
            }
            catch (const std::exception& e)
            {
                BOOST_LOG_TRIVIAL(error) << "Error during agent execution: " << e.what();
            }
            catch (...)
            {
                BOOST_LOG_TRIVIAL(error) << "Error during agent execution: unknown";
            }
            _sock.close();
        }
        delete this;
    }

    void do_read(boost::asio::mutable_buffer buf)
    {
        while(true)
        {
            try
            {
                read(_sock, buf);
                break;
            }
            catch(boost::system::system_error& e)
            {
                if(_sock.is_open() && e.code() != boost::asio::error::interrupted)
                    throw;
            }
        }
    }

    proto::response on_request(const proto::process::process_message& msg) noexcept
    {
        proto::response resp;
        resp.set_req_seq(msg.seq());
        resp.mutable_ok();
        try
        {
            if(msg.has_resp())
                throw bad_message_error{"Expecting request"};

            if(msg.req().has_hello())
            {
                if(msg.req().hello().pid())
                    throw std::runtime_error{"Giving pid not supported"};
                resp.mutable_ok()->mutable_pid()->set_pid(getpid());
                return resp;
            }
            else if(msg.req().has_add_tp())
            {
                if(!msg.req().add_tp().has_tp())
                    throw bad_message_error{"No tracepoint"};
                tracepoint_info tp_info;
                tp_info.name = msg.req().add_tp().tp().name();
                if(tp_info.name.empty())
                    tp_info.name = next_tp();
                if(msg.req().add_tp().tp().symbol().empty())
                    tp_info.loc = msg.req().add_tp().tp().address();
                else
                    tp_info.loc = msg.req().add_tp().tp().symbol();
                tp_info.tracer = msg.req().add_tp().tracer();
                tp_info.tracer_args.insert(
                    tp_info.tracer_args.begin(),
                    msg.req().add_tp().tracer_args().begin(),
                    msg.req().add_tp().tracer_args().end()
                );
                tp_info.entry_exit = msg.req().add_tp().entry_exit();

                resp.mutable_ok()->mutable_tp_created()->set_name(tp_info.name);
                create_tp(std::move(tp_info));
            }
            else if(msg.req().has_remove_tp())
            {
                remove_tp(msg.req().remove_tp().name());
            }
            else if(msg.req().has_list_tp())
            {
                resp.mutable_ok()->mutable_tps();
                resp.mutable_ok()->mutable_tps();
                for(const auto& tp : _tps)
                {
                    proto::tracepoint* resp_tp = resp.mutable_ok()->mutable_tps()->add_tp();
                    resp_tp->set_name(tp.name);
                    if(std::holds_alternative<std::string>(tp.loc))
                        resp_tp->set_symbol(std::get<std::string>(tp.loc));
                    else
                        resp_tp->set_address(std::get<uintptr_t>(tp.loc));
                }
            }
            else if(msg.req().has_list_sym())
            {
                resp.mutable_ok()->mutable_sym_list();
                for(const auto& sym : process::process::this_process().elf().get_section(".symtab").as_symtab())
                {
                    if(sym.get_data().type() == elf::stt::func)
                        resp.mutable_ok()->mutable_sym_list()->add_sym(sym.get_name());
                }
            }
        }
        catch(const agent_error& e)
        {
            resp.mutable_err()->set_type(e.category());
            resp.mutable_err()->set_msg(e.what());
        }
        catch(const fasttp::fasttp_error& e)
        {
            resp.mutable_err()->set_type("tracepoint_error");
            resp.mutable_err()->set_msg(e.what());
        }
        catch(const std::exception& e)
        {
            resp.mutable_err()->set_type("internal_error");
            resp.mutable_err()->set_msg(e.what());
        }
        catch(...)
        {
            resp.mutable_err()->set_type("internal_error");
        }
        return resp;
    }

    void create_tp(tracepoint_info&& info)
    {
        std::unique_ptr<fasttp::location> loc;
        void* addr{nullptr};
        if(std::holds_alternative<std::string>(info.loc))
        {
            fasttp::symbol_location symloc{std::get<std::string>(info.loc)};
            addr = symloc.resolve(process::process::this_process());
            loc = std::make_unique<fasttp::addr_location>(addr);
        }
        else
        {
            addr = reinterpret_cast<void*>(std::get<uintptr_t>(info.loc));
            loc = std::make_unique<fasttp::addr_location>(addr);
        }
        for(const auto& tp : _tps)
        {
            if(info.name == tp.name)
                throw invalid_tracepoint_error{"tracepoint named" + info.name + " already exists"};
            if(tp.tp.location() == addr)
                throw invalid_tracepoint_error{"tracepoint at " + dyntrace::to_hex_string(addr) + " already exists"};
        }
        dyntrace::tracer::handler h;
        if(info.entry_exit)
            h = _registry.get_factory(info.tracer).create_entry_exit_handler(info.tracer_args);
        else
            h = _registry.get_factory(info.tracer).create_point_handler(info.tracer_args);
        info.tp = fasttp::tracepoint{*loc, std::move(h)};
        _tps.push_back(std::move(info));
    }

    void remove_tp(const std::string& name)
    {
        for(auto it = _tps.begin(); it != _tps.end(); ++it)
        {
            if(it->name == name)
            {
                _tps.erase(it);
                return;
            }
        }
        throw invalid_tracepoint_error{"tracepoint named " + name + " does not exist"};
    }

    std::string next_tp() noexcept
    {
        return "tp-" + std::to_string(_next_tp++);
    }

    uint64_t _next_seq{1};
    uint64_t _next_tp{0};
    std::list<tracepoint_info> _tps;
    dyntrace::agent::tracer_registry _registry;

    boost::asio::io_context _ctx;
    boost::asio::local::stream_protocol::socket _sock;
    std::atomic<bool> _done{false};
};

namespace
{
    agent_main* _agent;
}

void __attribute__((constructor)) init()
{
    _agent = new agent_main;
}

void __attribute__((destructor)) fini()
{
    _agent->stop();
}