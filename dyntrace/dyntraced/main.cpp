
#include <experimental/filesystem>
#include <iostream>
#include <sstream>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/program_options.hpp>
#include <boost/range/irange.hpp>
#include <boost/thread/thread_pool.hpp>

#include <fcntl.h>
#include <grp.h>
#include <sys/stat.h>

#include <config.hpp>

#include "command.hpp"
#include "process.hpp"

namespace asio = boost::asio;
namespace comm = dyntrace::comm;
namespace fs = std::experimental::filesystem;
namespace po = boost::program_options;

using namespace std::string_literals;
using namespace std::string_view_literals;

[[noreturn]]
void do_exit(std::string_view msg, int code = 1)
{
    std::cerr << msg << "\n";
    exit(code);
}

struct cmdline
{
    bool daemonize;
    size_t threads;
};

gid_t get_dyntrace_group()
{
    if(auto grp = getgrnam(dyntrace::config::group_name))
    {
        return grp->gr_gid;
    }
    else
        do_exit("Could not find group '"s + dyntrace::config::group_name + "'"s);
}

cmdline parse_args(int argc, const char** argv)
{
    cmdline args{};
    po::options_description desc(
        std::string{argv[0]} + " [options...]\n"
        "Available options:"
    );

    desc.add_options()
        ("daemonize", po::bool_switch(&args.daemonize), "Run as a daemon\n")
        ("thread,t", po::value(&args.threads)->default_value(1), "Number of threads\n")
    ;

    try
    {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    }
    catch(const po::error& e)
    {
        std::cerr << e.what() << "\n";
        std::cerr << desc;
        exit(1);
    }
    catch(const std::exception& e)
    {
        do_exit("Error while parsing arguments: "s + e.what());
    }
    catch(...)
    {
        do_exit("Unknown error"sv);
    }

    if(args.threads == 0)
        do_exit("Invalid number of threads"sv);

    return args;
}

void lock_daemon()
{
    auto lock_file_path = fs::path{dyntrace::config::lock_file_name};
    auto lock_file_fd = open(lock_file_path.c_str(), O_EXCL | O_WRONLY | O_CREAT);
    if(lock_file_fd == -1)
    {
        if(errno == EEXIST)
            do_exit("dyntraced is already running"sv);
        else
            do_exit("Could not create lock file: "s + strerror(errno));
    }
    auto strpid = std::to_string(getpid());
    write(lock_file_fd, strpid.data(), strpid.size());
    close(lock_file_fd);
    chmod(lock_file_path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
}

void setup_daemon(bool daemonize)
{
    if(mkdir(dyntrace::config::working_directory, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0 && errno != EEXIST)
        do_exit("Could not create '"s + dyntrace::config::working_directory + "': "s + strerror(errno));

    if(chdir(dyntrace::config::working_directory) != 0)
        do_exit("Could not change directory: "s + strerror(errno));

    lock_daemon();

    if(daemonize)
        daemon(true, true);
}

void init_logging(bool daemon)
{
    using namespace boost::log;
    auto core = core::get();
    if(daemon)
    {
        auto syslog = boost::make_shared<sinks::syslog_backend>(
            keywords::facility = sinks::syslog::daemon,
            keywords::use_impl = sinks::syslog::native
        );
        core->add_sink(boost::make_shared<sinks::synchronous_sink<sinks::syslog_backend>>(syslog));
    }
    else
    {
        auto out = boost::make_shared<sinks::text_ostream_backend>();
        out->add_stream(boost::shared_ptr<std::ostream>{&std::cout, [](auto) {}});
        out->auto_flush(true);
        core->add_sink(boost::make_shared<sinks::synchronous_sink<sinks::text_ostream_backend>>(out));
    }
}

int main(int argc, const char** argv)
{
#ifndef _DEBUG
    if(geteuid() != 0)
    {
        do_exit("You must be root to run this"sv);
    }
#endif
    auto grp = get_dyntrace_group();
    auto args = parse_args(argc, argv);
    setup_daemon(args.daemonize);
    init_logging(args.daemonize);

    // From this point, we must not quit unless we clean up the files.
    // We also may be a daemon.

    int ret = 0;
    try
    {
        asio::io_context ctx;

        dyntrace::d::process_registry reg;

        auto command_factory = comm::local::make_connection_factory<dyntrace::d::command_connection>(&reg);
        comm::local::server command_srv{ctx, comm::local::endpoint{dyntrace::config::command_socket_name}, command_factory};
        auto process_factory = [&reg](comm::local::server* srv, comm::local::socket sock)
        {
            auto conn = dyntrace::make_refcnt<dyntrace::d::process_connection>(srv, std::move(sock), &reg);
            dyntrace::proto::process::request req;
            req.mutable_hello();
            conn->send(req, [&reg, conn](const dyntrace::proto::response& resp)
            {
                if(resp.has_ok())
                {
                    if(resp.ok().has_pid())
                    {
                        conn->set_pid(resp.ok().pid().pid());
                        reg.add(resp.ok().pid().pid(), conn.get());
                        return;
                    }
                }
                conn->close();
                BOOST_LOG_TRIVIAL(error) << "Invalid response for hello" << resp.DebugString();
            });
            return conn;
        };
        comm::local::server process_srv{ctx, comm::local::endpoint{dyntrace::config::process_socket_name}, process_factory};

        chmod(dyntrace::config::command_socket_name, S_IRWXU | S_IRWXG);
        chown(dyntrace::config::command_socket_name, geteuid(), grp);
        chmod(dyntrace::config::process_socket_name, S_IRWXU | S_IRWXG);
        chown(dyntrace::config::process_socket_name, geteuid(), grp);

        asio::signal_set sigs{ctx, SIGINT, SIGTERM};
        sigs.async_wait(
            [&ctx, &command_srv, &process_srv](const boost::system::error_code& err, int sig)
            {
                command_srv.stop();
                process_srv.stop();
                ctx.stop();
            }
        );

        command_srv.start();
        process_srv.start();

        boost::thread_group tg;
        for (auto _ : boost::irange<size_t>(0, args.threads - 1))
        {
            (void)_;
            tg.create_thread(
                [&ctx]()
                {
                    ctx.run();
                }
            );
        }

        ctx.run();
        tg.join_all();
    }
    catch(const std::exception& e)
    {
        std::cerr << "Error during execution: " << e.what() << "(" << typeid(e).name() << ")\n";
        ret = 1;
    }
    unlink(dyntrace::config::command_socket_name);
    unlink(dyntrace::config::process_socket_name);
    unlink(dyntrace::config::lock_file_name);
    rmdir(dyntrace::config::working_directory);
    return ret;
}