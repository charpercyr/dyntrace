#ifndef DYNTRACE_DYNTRACED_REGISTRY_HPP_
#define DYNTRACE_DYNTRACED_REGISTRY_HPP_

#include "local.hpp"

#include "dyntrace/util/locked.hpp"

#include <optional>

namespace dyntrace::d
{
    class process_registry;

    class process_connection final : public comm::local::process_connection
    {
    public:
        using message_type = proto::process::process_message;
        using request_type = proto::process::request;
        using response_type = proto::response;
        using base_type = comm::local::process_connection;
        using request_done_callback = std::function<void(const response_type&)>;

        process_connection(comm::local::server* srv, comm::local::socket sock, process_registry* reg) noexcept
            : base_type{srv, std::move(sock)}, _reg{reg} {}
        ~process_connection() override;

        void set_pid(pid_t pid) noexcept
        {
            _pid = pid;
        }
        pid_t pid() const noexcept
        {
            return _pid.value_or(-1);
        }

        void send(const request_type& req, request_done_callback on_done);

    private:
        void on_message(const message_type& msg) override;
        void on_error(uint64_t seq, const std::exception* e) override;

        process_registry* _reg;
        std::optional<pid_t> _pid;
        dyntrace::locked<std::unordered_map<uint64_t, request_done_callback>> _pending;
    };

    class process_registry
    {
        using registry_type = dyntrace::locked<std::unordered_map<pid_t, process_connection*>>;
    public:
        process_registry(const process_registry&) = delete;
        process_registry(process_registry&&) = delete;
        process_registry& operator=(const process_registry&) = delete;
        process_registry& operator=(process_registry&&) = delete;

        process_registry() noexcept = default;

        process_connection* add(pid_t pid, process_connection* conn)
        {
            auto reg = _reg.lock();
            auto it = reg->insert_or_assign(pid, conn).first;
            return it->second;
        }
        void remove(pid_t pid) noexcept
        {
            auto reg = _reg.lock();
            reg->erase(pid);
        }

        process_connection* get(pid_t pid) noexcept
        {
            auto reg = _reg.lock();
            auto it = reg->find(pid);
            if(it != reg->end())
                return it->second;
            else
                return nullptr;
        }

        std::vector<pid_t> all_processes() const noexcept
        {
            std::vector<pid_t> ret;
            auto reg = _reg.lock();
            for(const auto& p : *reg)
            {
                ret.push_back(p.first);
            }
            return ret;
        }

    private:
        registry_type _reg;
    };

    inline process_connection::~process_connection()
    {
        if(_pid)
            _reg->remove(_pid.value());
    }
}

#endif