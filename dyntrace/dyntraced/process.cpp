#include "process.hpp"

#include <boost/log/trivial.hpp>

using namespace dyntrace::d;

void process_handler::on_hello(size_t seq, const dyntrace::comm::hello_body &hello)
{
    BOOST_LOG_TRIVIAL(info) << "hello " << hello.pid << "\n";
}

void process_handler::on_bye(size_t seq, const dyntrace::comm::bye_body &bye)
{
    BOOST_LOG_TRIVIAL(info) << "bye\n";
}