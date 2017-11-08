#ifndef DYNTRACE_INJECT_INJECTOR_HPP_
#define DYNTRACE_INJECT_INJECTOR_HPP_

#include "remote.hpp"

#include <process/process.hpp>
#include <list>

namespace dyntrace::inject
{
    namespace _detail
    {
        struct remote_dlopen_args
        {
            alignas(void*) void*(*dlopen)(const char*, int);
            alignas(void*) char* name;
            alignas(void*) int flags;
            alignas(void*) void* handle;
        };

        struct remote_dlclose_args
        {
            alignas(void*) void(*dlclose)(void*);
            alignas(void*) void* handle;
        };
    }

    template<typename Target>
    class injector
    {
        using remote_ptr = inject::remote_ptr<Target>;
        using ptrace = inject::ptrace<Target>;
        using remote = inject::remote<Target>

        using libs_list = std::list<remote_ptr>;
        using libs_list_iterator = typename libs_list::iterator;

    public:

        class handle
        {

            friend class injector;
            ~handle()
            {
                if(_au)
                {
                    _inj.remove(*this);
                }
            }

            bool auto_unlink() const noexcept
            {
                return _au;
            }
            void auto_unlink(bool value) noexcept
            {
                _au = value;
            }

        private:
            handle(injector& inj, libs_list_iterator it, bool auto_unlink_ = false)
                : _inj{inj}, _it{it}, _au{auto_unlink_} {}

            injector& _inj;
            libs_list_iterator _it;
            bool _au;
        };

        explicit injector(const process::process& proc)
            : _proc{proc} {}
        ~injector()
        {

        }

        handle inject(const char* name, bool auto_unlink = false)
        {
        }

        void remove(handle& h)
        {
            h.auto_unlink(false);
            _remove(h._it);
        }

    private:

        void _remove(libs_list_iterator it)
        {
            remote_ptr lib = *it;
            _libs.remove(it);
        }

        const process::process& _proc;
        libs_list _libs;
    };
}

#endif