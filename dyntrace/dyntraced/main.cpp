
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/thread/thread_pool.hpp>

#include <experimental/filesystem>

#include <dyntrace/comm/local.hpp>

using namespace std;
using namespace std::chrono_literals;

namespace asio = boost::asio;
namespace comm = dyntrace::comm;
namespace fs = std::experimental::filesystem;
namespace po = boost::program_options;

class my_handler : public comm::local::connection_handler
{
public:
    explicit my_handler(comm::local::handler& h, comm::local::socket&& sock) noexcept
        : comm::local::connection_handler{h, std::move(sock)}
    {
        printf("New handler !\n");
    }

protected:
    void on_receive(const comm::local::connection_handler::buffer_type& buf, size_t size) override
    {
        printf("Received: %s", reinterpret_cast<const char*>(buf.data()));
    }
};

int main(int argc, const char** argv)
{
    po::options_description desc("Available options");

    string working_directory;
    string command_socket_path;
    string process_socket_path;
    size_t n_threads;
    po::variables_map vm;

    desc.add_options()
        ("help,h", "Shows help")
        ("daemonize", "Run as a daemon")
        ("dir", po::value(&working_directory)->default_value("/run/dyntraced"), "Working directory of dyntraced")
        ("command-socket", po::value(&command_socket_path)->default_value("command.sock"), "Command socket file name")
        ("process-socket", po::value(&process_socket_path)->default_value("process.sock"), "Process socket file name")
        ("thread,t", po::value(&n_threads)->default_value(1), "Number of threads to use")
    ;
    try
    {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    }
    catch(po::error& e)
    {
        cerr << e.what() << '\n';
        cerr << desc;
        return 1;
    }
    catch (exception& e)
    {
        cerr << "Error during argument parsing: " << e.what() << '\n';
        return 1;
    }

    if(vm.count("help"))
    {
        cout << desc;
        return 0;
    }

    if(vm.count("daemonize"))
    {
        daemon(false, true);
    }

    if(n_threads == 0)
    {
        cerr << "Invalid number of threads\n";
        return 1;
    }

    fs::path command_socket = fs::path{working_directory} / fs::path{command_socket_path};
    fs::path process_socket = fs::path{working_directory} / fs::path{process_socket_path};

    try
    {
        asio::io_context ctx;
        using server = comm::local::server;
        using handler = comm::local::simple_handler<my_handler>;

        handler h;
        server command_server{ctx, h, server::endpoint{command_socket.string()}};
        server process_server{ctx, h, server::endpoint{process_socket.string()}};

        asio::signal_set sig_set{ctx, SIGINT, SIGTERM};
        sig_set.async_wait(
            [&ctx, &command_server, &process_server](const boost::system::error_code& err, int sig)
            {
                command_server.stop();
                process_server.stop();
                ctx.stop();
            }
        );

        boost::thread_group tg;
        for (size_t i = 0; i < n_threads - 1; ++i)
            tg.create_thread(
                [&ctx]()
                {
                    ctx.run();
                }
            );
        ctx.run();
        tg.join_all();
    }
    catch(exception& e)
    {
        cerr << "Error during execution: " << e.what() << endl;
    }

    unlink(command_socket.c_str());
    unlink(process_socket.c_str());

    return 0;
}
