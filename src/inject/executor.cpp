#include "dyntrace/inject/executor.hpp"

#include "arch/executor.hpp"

using namespace dyntrace::inject;

executor::executor(process_ptr proc)
    : _impl{std::make_unique<arch_executor>(proc)}, _proc{proc}
{

}

executor::~executor() = default;

uintptr_t executor::remote_call(remote_ptr func, const remote_args &args)
{
    return _impl->remote_call(func, args);
}

void executor::copy(remote_ptr to, const void *from, size_t size)
{
    return _impl->get_ptrace().write(to, from, size);
}

void executor::copy(void *to, remote_ptr from, size_t size)
{
    _impl->get_ptrace().read(to, from, size);
}

static const auto libc_regex = std::regex{"libc-.*\\.so"};

remote_malloc dyntrace::inject::make_malloc(executor &e)
{
    auto malloc_func = e.create<remote_ptr(size_t)>("malloc", libc_regex);
    auto free_func = e.create<void(remote_ptr)>("free", libc_regex);
    return [malloc_func, free_func](size_t size)
    {
        return unique_remote_ptr{malloc_func(size), free_func};
    };
}