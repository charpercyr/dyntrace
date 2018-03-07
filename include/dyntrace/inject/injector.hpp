#ifndef DYNTRACE_INJECT_INJECTOR_HPP_
#define DYNTRACE_INJECT_INJECTOR_HPP_

#include "executor.hpp"

namespace dyntrace::inject
{
    using remote_clone_sig = int(remote_ptr, remote_ptr, int, remote_ptr, pid_t, remote_ptr, pid_t);
    using remote_clone = std::function<remote_clone_sig>;

    class injector
    {
        friend class library_handle;
    public:

        explicit injector(pid_t pid)
            : injector{std::make_shared<const process::process>(pid)} {}
        explicit injector(process_ptr proc);

        remote_ptr inject(const std::string& path);
        void remove(remote_ptr lib);

        process_ptr get_process() const noexcept
        {
            return _e.get_process();
        }

        executor& get_executor() noexcept
        {
            return _e;
        }

    private:

        executor _e;
        remote_function<remote_ptr(remote_ptr, int)> _dlopen;
        remote_function<int(remote_ptr)> _dlclose;
        remote_malloc _malloc;
    };
}

#endif