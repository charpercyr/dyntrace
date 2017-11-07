#ifndef DYNTRACE_INJECT_AUTO_PTR_HPP_
#define DYNTRACE_INJECT_AUTO_PTR_HPP_

#include <cstddef>

#include "remote_util.hpp"
#include "ptrace.hpp"

#include <functional>
#include <memory>

namespace dyntrace::inject
{
    template<typename Arch>
    class remote_auto_ptr
    {
    public:
        remote_auto_ptr(remote_ptr<Arch> ptr, std::function<void(remote_ptr<Arch>)> del)
            : _ptr{ptr}, _del{del} {}
        ~remote_auto_ptr()
        {
            _del(_ptr);
        }

        template<typename T>
        T* ptr() const noexcept
        {
            return _ptr.template ptr<T>();
        }

        operator remote_ptr<Arch>() const noexcept
        {
            return _ptr;
        }

        remote_ptr<Arch> get() const noexcept
        {
            return _ptr;
        }

    private:
        remote_ptr<Arch> _ptr;
        std::function<void(remote_ptr<Arch>)> _del;
    };

    template<typename Arch>
    using malloc_remote_ptr = remote_function<Arch, remote_ptr<Arch>(size_t)>;
    template<typename Arch>
    using free_remote_ptr = remote_function<Arch, void(remote_ptr<Arch>)>;
    template<typename Arch>
    using mmap_remote_ptr = remote_function<Arch, remote_ptr<Arch>(remote_ptr<Arch>, size_t, int, int, int, off_t)>;
    template<typename Arch>
    using munmap_remote_ptr = remote_function<Arch, int(remote_ptr<Arch>, size_t)>;

    template<typename Arch>
    remote_auto_ptr<Arch> malloc_ptr(malloc_remote_ptr<Arch> malloc_, free_remote_ptr<Arch> free_, size_t size)
    {
        return remote_auto_ptr<Arch>{malloc_(size), [free_](remote_ptr<Arch> ptr)
        {
            free_(ptr);
        }};
    }

    template<typename Arch>
    remote_auto_ptr<Arch> mmap_ptr(mmap_remote_ptr<Arch> mmap_, munmap_remote_ptr<Arch> munmap_, remote_ptr<Arch> ptr, size_t size, int prot, int flags, int fd, off_t offset)
    {
        return remote_auto_ptr<Arch>{mmap_(ptr, size, prot, flags, fd, offset), [munmap_, size](remote_ptr<Arch> _ptr)
        {
            munmap_(_ptr, size);
        }};
    }
}

#endif