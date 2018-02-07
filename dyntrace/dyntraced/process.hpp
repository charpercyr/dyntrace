#ifndef DYNTRACE_DYNTRACED_PROCESS_HPP_
#define DYNTRACE_DYNTRACED_PROCESS_HPP_

#include <dyntrace/comm/local.hpp>

namespace dyntrace::d
{
    class process_handler : public dyntrace::comm::local::process_handler
    {
    public:
        using dyntrace::comm::local::process_handler::process_handler;

    protected:
        void on_hello(size_t seq, const dyntrace::comm::hello_body& hello) override;
        void on_bye(size_t seq, const dyntrace::comm::bye_body& bye) override;

    private:
    };
}

#endif