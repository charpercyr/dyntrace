#ifndef DYNTRACE_INJECT_INJECTOR_HPP_
#define DYNTRACE_INJECT_INJECTOR_HPP_

#include "auto_ptr.hpp"

#include <process/process.hpp>
#include <list>

namespace dyntrace::inject
{
    namespace _detail
    {
        struct dlopen_args
        {
            void*(*dlopen)(const char*, int);
            char* name;
            int mode;
        };

        struct dlclose_args
        {
            void(*dlclose)(void*);
            void* handle;
        };

        template<typename Args>
        struct clone_args
        {
            Args args;
            void* ret;
        };

        extern "C" void* do_dlopen(clone_args<dlopen_args>* args);
        extern "C" void* do_dlclose(clone_args<dlclose_args>* args);
    }

    template<typename Target>
    class injector
    {
        using remote_ptr = inject::remote_ptr<Target>;
        using ptrace = inject::ptrace<Target>;
        using remote_malloc = inject::remote_function<Target, remote_ptr(size_t)>;
        using remote_free = inject::remote_function<Target, void(remote_ptr)>;
        using remote_dlopen = inject::remote_function<Target, remote_ptr(remote_ptr, int)>;
        using remote_mmap = inject::remote_function<Target, remote_ptr(remote_ptr, size_t, int, int, int, off_t)>;
        using remote_munmap = inject::remote_function<Target, int(remote_ptr, size_t)>;
        using remote_clone = inject::remote_function<Target, int(remote_ptr, remote_ptr, int, remote_ptr, remote_ptr, remote_ptr, remote_ptr)>;

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
            std::regex libc{".*libc.*"};
            auto malloc_addr = _proc.get("malloc", libc);
            auto free_addr = _proc.get("free", libc);
            auto dlopen_addr = _proc.get("__libc_dlopen_mode", libc);
            auto mmap_addr = _proc.get("mmap", libc);
            auto munmap_addr = _proc.get("munmap", libc);
            auto clone_addr = _proc.get("clone", libc);

            ptrace pt{_proc.pid()};
            remote_malloc r_malloc{pt, malloc_addr.value};
            remote_free r_free{pt, free_addr.value};
            remote_dlopen r_dlopen{pt, dlopen_addr.value};
            remote_mmap r_mmap{pt, mmap_addr.value};
            remote_munmap r_munmap{pt, munmap_addr.value};
            remote_clone r_clone{pt, clone_addr.value};

            auto call_dlopen_size = _proc.get("do_dlopen");
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