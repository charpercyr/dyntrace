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