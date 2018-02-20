
#include <atomic>
#include <chrono>
#include <thread>
#include <experimental/filesystem>

#include <boost/asio.hpp>

#include <dyntrace/comm/local.hpp>

#include <config.hpp>
#include <process.pb.h>
#include <util/barrier.hpp>

using namespace dyntrace;
namespace fs = std::experimental::filesystem;

class bad_message_error : public std::runtime_error
{
public:
    bad_message_error(const std::string& msg = "")
        : std::runtime_error{"bad_message"}, _msg{msg} {}

    const std::string& msg() const noexcept
    {
        return _msg;
    }
private:
    std::string _msg;
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
        try
        {
            static const auto sock_file = fs::path{config::working_directory} / fs::path{config::process_socket_name};
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
                *reinterpret_cast<uint32_t*>(buf.data()) = data.size();
                memcpy(buf.data() + sizeof(uint32_t), data.data(), data.size());
                write(_sock, buffer(buf));
            }
        }
        catch(const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Error during agent execution: " << e.what();
        }
        catch(...)
        {
            BOOST_LOG_TRIVIAL(error) << "Error during agent execution: unknown";
        }
    }

    proto::response on_request(const proto::process::process_message& msg) noexcept
    {
        proto::response resp;
        resp.set_req_seq(msg.seq());
        try
        {
            if(msg.has_resp())
                throw bad_message_error{"Expecting request"};

            if(msg.req().has_hello())
            {
                if(_done_hello)
                    throw bad_message_error{"Already done hello"};
                if(msg.req().hello().pid())
                {
                    throw std::runtime_error{"Giving pid not supported"};
                }
                resp.mutable_ok()->mutable_pid()->set_pid(getpid());
                _done_hello = true;
                return resp;
            }
            else
                throw std::runtime_error{"Request not supported"};
        }
        catch(const bad_message_error& e)
        {
            resp.mutable_err()->set_type("bad_message");
            resp.mutable_err()->set_msg(e.msg());
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

    uint64_t _next_seq{0};
    bool _done_hello{false};

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