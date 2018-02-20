
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
        static const auto sock_file = fs::path{config::working_directory} / fs::path{config::process_socket_name};
        boost::system::error_code err;
        using namespace boost::asio;

        while(_done.load(std::memory_order_relaxed)) // Try connecting
        {
            _sock.connect(sock_file.c_str(), err);
            if(!err)
                break;
            else // try again later
                std::this_thread::sleep_for(std::chrono::seconds{5});
        }

        try
        {
            while (_done.load(std::memory_order_relaxed))
            {
                uint32_t to_recv;
                read(_sock, buffer(&to_recv, sizeof(to_recv)));
                std::string data(to_recv, 0);
                read(_sock, buffer(data));
                proto::process::process_message msg;
                msg.ParseFromString(data);
                auto resp = on_request(msg);
                resp.SerializeToString(&data);
                write(_sock, buffer(data));
            }
        }
        catch(const boost::system::system_error& err)
        {
//            if(err.code() != boost::asio::error::eof)
//                BOOST_LOG_TRIVIAL(error) << "Error during send: " << err.what();
        }
    }

    proto::response on_request(const proto::process::process_message& msg)
    {
        return {};
    }

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