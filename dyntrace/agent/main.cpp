
#include <atomic>
#include <chrono>
#include <thread>
#include <variant>
#include <experimental/filesystem>

#include <boost/asio.hpp>

#include <config.hpp>
#include <process.pb.h>
#include <dyntrace/comm/local.hpp>

#include <fasttp/fasttp.hpp>
#include <util/barrier.hpp>
#include <fasttp/error.hpp>

using namespace dyntrace;
namespace fs = std::experimental::filesystem;

class bad_message_error : public std::runtime_error
{
public:
    explicit bad_message_error(const std::string& msg = "")
        : std::runtime_error{"bad_message"}, _msg{msg} {}

    const std::string& msg() const noexcept
    {
        return _msg;
    }
private:
    std::string _msg;
};

class invalid_tracepoint_error : public std::runtime_error
{
public:
    explicit invalid_tracepoint_error(const std::string& msg = "")
        : std::runtime_error{"invalid_tracepoint_error"}, _msg{msg} {}

    const std::string& msg() const noexcept
    {
        return _msg;
    }
private:
    std::string _msg;
};

struct tracepoint_info
{
    dyntrace::fasttp::tracepoint tp;
    std::variant<std::string, uintptr_t> loc;
    std::string name;
    std::string tracer;
};

class agent_main
{
public:
    agent_main()
        : _sock{_ctx}, _th{&agent_main::run, this} {}
    ~agent_main()
    {
        _done = true;
        _sock.close();
        _th.join();
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
                    read(_sock, buffer(&to_recv, sizeof(to_recv)));
                    std::string data(to_recv, 0);
                    read(_sock, buffer(data));
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
        }
        catch(const bad_message_error& e)
        {
            resp.mutable_err()->set_type("bad_message");
            resp.mutable_err()->set_msg(e.msg());
        }
        catch(const invalid_tracepoint_error& e)
        {
            resp.mutable_err()->set_type("invalid_tracepoint_error");
            resp.mutable_err()->set_msg(e.msg());
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
            if(info.name == tp.name || addr == tp.tp.location())
                throw invalid_tracepoint_error{"tracepoint already exists"};
        }
        info.tp = fasttp::tracepoint{*loc, [this, tracer = info.tracer](const void* from, const arch::regs& regs)
        {
            printf("tracepoint %p, handler=%s\n", from, tracer.c_str());
        }};
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
    }

    std::string next_tp() noexcept
    {
        return "tp-" + std::to_string(_next_tp++);
    }

    uint64_t _next_seq{1};
    uint64_t _next_tp{0};
    std::list<tracepoint_info> _tps;

    boost::asio::io_context _ctx;
    comm::local::socket _sock;
    std::atomic<bool> _done{false};
    std::thread _th;
};

namespace
{
    agent_main* agent;
}

void __attribute__((constructor)) init()
{
    agent = new agent_main;
}

void __attribute__((destructor)) fini()
{
    delete agent;
}