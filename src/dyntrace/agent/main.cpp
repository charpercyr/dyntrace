
#include "tracepoints.hpp"

#include "dyntrace/fasttp/fasttp.hpp"
#include "dyntrace/fasttp/error.hpp"
#include "dyntrace/process/process.hpp"

#include <config.hpp>
#include <process.pb.h>

#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>

#include <atomic>
#include <chrono>
#include <dlfcn.h>
#include <list>
#include <thread>
#include <variant>
#include <experimental/filesystem>

using namespace dyntrace;
using namespace dyntrace::agent;
namespace fs = std::experimental::filesystem;

using malloc_sig = void*(*)(size_t);
using free_sig = void(*)(void*);

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
        using namespace std::string_literals;
        proto::response resp;
        resp.set_req_seq(msg.seq());
        resp.mutable_ok();
        try
        {
            if(msg.has_resp())
                throw bad_message_error{"Expecting request"};

            if(msg.req().has_hello())
            {
                resp.mutable_ok()->mutable_pid()->set_pid(getpid());
            }
            else if(msg.req().has_add_tp())
            {
                auto r = _registry.add(msg.req().add_tp());
                if(r.first.empty())
                {
                    resp.mutable_err()->set_type("tracepoint_error");
                    std::string err_msg;
                    for(auto&& e : r.second)
                    {
                        err_msg += "#"s + std::to_string(e.first) + ": "s + e.second;
                    }
                    resp.mutable_err()->set_msg(std::move(err_msg));
                }
                else
                {
                    resp.mutable_ok()->mutable_tp_created()->set_name(std::move(r.first));
                    for (auto &&e : r.second)
                    {
                        auto failed = resp.mutable_ok()->mutable_tp_created()->add_failed();
                        failed->set_id(e.first);
                        failed->set_msg(std::move(e.second));
                    }
                }
            }
            else if(msg.req().has_remove_tp())
            {
                _registry.remove(msg.req().remove_tp());
            }
            else if(msg.req().has_list_tp())
            {
                for(auto&& [name, tg] : _registry.groups())
                {
                    auto g = resp.mutable_ok()->mutable_tps()->add_tgs();
                    g->set_name(name);
                    if(std::holds_alternative<tracepoint_group_filter>(tg.location))
                        g->set_filter(std::get<tracepoint_group_filter>(tg.location).filter);
                    else if(std::holds_alternative<tracepoint_group_regex>(tg.location))
                        g->set_regex(std::get<tracepoint_group_regex>(tg.location).regex);
                    else
                        g->set_address(std::get<uintptr_t>(tg.location));
                    g->set_entry_exit(tg.entry_exit);
                    g->set_tracer(tg.tracer);
                    for(auto&& arg : tg.tracer_args)
                        g->add_tracer_args(arg);
                    for(size_t i = 0; i < tg.tps.size(); ++i)
                    {
                        // Skip deleted tracepoints
                        if(!tg.tps[i].failed && !tg.tps[i].tp)
                            continue;
                        auto tp = g->add_tps();
                        if(tg.tps[i].symbol)
                            tp->set_symbol(tg.tps[i].symbol.value());
                        if(tg.tps[i].failed)
                            tp->set_failed(true);
                        else
                            tp->set_address(reinterpret_cast<uintptr_t>(tg.tps[i].tp.location()));
                        tp->set_id(i);
                    }
                }
            }
            else if(msg.req().has_list_sym())
            {
                resp.mutable_ok()->mutable_syms();
                auto symtab = process::process::this_process().get_elf().get_section(".symtab");
                if(symtab.valid())
                {
                    for(auto&& sym : symtab.as_symtab())
                    {
                        auto s = resp.mutable_ok()->mutable_syms()->add_sym();
                        s->set_name(sym.name().data());
                        s->set_address(sym.value() + process::process::this_process().base());
                    }
                }
            }
        }
        catch(const agent_error& e)
        {
            resp.mutable_err()->set_type(e.category());
            resp.mutable_err()->set_msg(e.what());
        }
        catch(const tracer::tracer_error& e)
        {
            resp.mutable_err()->set_type("tracer_error");
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

    std::string next_tp() noexcept
    {
        return "tp-" + std::to_string(_next_tp++);
    }

    uint64_t _next_seq{1};
    uint64_t _next_tp{0};
    std::list<tracepoint_info> _tps;
    dyntrace::agent::tracepoint_registry _registry;

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
}