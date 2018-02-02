#ifndef DYNTRACE_COMM_HANDLER_HPP_
#define DYNTRACE_COMM_HANDLER_HPP_

#include <array>
#include <cstddef>
#include <memory>
#include <unordered_map>
#include <boost/system/error_code.hpp>

namespace dyntrace::comm
{
    template<typename>
    class handler;

    template<typename Proto>
    class connection_handler
    {
    public:
        using socket = typename Proto::socket;
        using buffer_type = std::array<std::byte, 4096>;

        connection_handler(handler<Proto>& h, socket&& sock) noexcept
            : _h{h}, _sock{std::move(sock)} {}

        void start()
        {
            _sock.async_receive(
                _buf,
                [this](const boost::system::error_code& err, std::size_t size)
                {
                    if(err)
                        on_error(err);
                    else
                        on_receive(_buf, size);
                }
            );
        }

        virtual ~connection_handler() = default;

        void close() noexcept;

    protected:
        virtual void on_receive(const buffer_type& buf, size_t size) = 0;
        virtual void on_error(const boost::system::error_code& err) {}

    private:
        std::array<std::byte, 4096> _buf;
        handler<Proto>& _h;
        socket _sock;
    };

    template<typename Proto>
    class handler
    {
    public:
        using socket = typename Proto::socket;
        using connection_handler = dyntrace::comm::connection_handler<Proto>;

        virtual ~handler() = default;

        void accept(socket&& sock)
        {
            if(auto ptr = on_accept(std::move(sock)))
            {
                auto addr = ptr.get();
                _handlers.insert(std::make_pair(addr, std::move(ptr)));
            }
        }

        void close(connection_handler* handler)
        {
            auto it = _handlers.find(handler);
            if(it != _handlers.end())
                _handlers.erase(it);
        }

    protected:
        virtual std::unique_ptr<connection_handler> on_accept(socket&& sock) = 0;

    private:
        std::unordered_map<connection_handler*, std::unique_ptr<connection_handler>> _handlers;
    };

    template<typename Proto, typename ConnectionHandler>
    class simple_handler : public handler<Proto>
    {
    public:
        using socket = typename handler<Proto>::socket;
        using connection_handler = typename handler<Proto>::connection_handler;

    protected:
        std::unique_ptr<connection_handler> on_accept(socket&& sock) override
        {
            return std::make_unique<ConnectionHandler>(*this, std::move(sock));
        }
    };

    template<typename Proto>
    void connection_handler<Proto>::close() noexcept
    {
        _h.close(this);
        _sock.close();
    }
}

#endif