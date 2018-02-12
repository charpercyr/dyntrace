#include "process.hpp"

#include <boost/log/trivial.hpp>

#include <iostream>

using namespace dyntrace::d;

void process_connection::on_hello(size_t seq, const dyntrace::comm::hello_body &hello)
{
    std::cout << "hello " << hello.pid << "\n";
}

void process_connection::on_bye(size_t seq, const dyntrace::comm::bye_body &bye)
{
    std::cout << "bye\n";
}

dyntrace::comm::response_sub process_connection::on_request(size_t seq, const dyntrace::comm::request_body &req)
{
    std::cout << "request\n";
    return dyntrace::comm::response_ok{dyntrace::comm::tracepoint_created{"tp-1"}};
}