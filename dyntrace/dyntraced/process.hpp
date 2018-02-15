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
        void on_hello(uint64_t seq, const dyntrace::proto::process::hello& hello) override;
        void on_bye(uint64_t seq, const dyntrace::proto::process::bye& bye) override;
        dyntrace::proto::response on_request(uint64_t seq, const dyntrace::proto::process::request& req) override;

    private:
    };
}

#endif