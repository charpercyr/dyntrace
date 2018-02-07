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