#ifndef DYNTRACE_DYNTRACED_PROCESS_HPP_
#define DYNTRACE_DYNTRACED_PROCESS_HPP_

#include <dyntrace/comm/local.hpp>

namespace dyntrace::d
{
    class process_connection : public dyntrace::comm::local::process_connection
    {
    public:
        using dyntrace::comm::local::process_connection::process_connection;

    protected:
        void on_hello(size_t seq, const dyntrace::comm::hello_body& hello) override;
        void on_bye(size_t seq, const dyntrace::comm::bye_body& bye) override;
        dyntrace::comm::response_sub on_request(size_t seq, const dyntrace::comm::request_body& req) override;

    private:
    };
}

#endif