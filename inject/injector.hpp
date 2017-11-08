#ifndef DYNTRACE_INJECT_INJECTOR_HPP_
#define DYNTRACE_INJECT_INJECTOR_HPP_

#include "remote.hpp"

#include <process/process.hpp>

#include <dlfcn.h>
#include <sys/mman.h>

#include <list>

namespace dyntrace::inject
{
    namespace _detail
    {
        struct remote_dlopen_args
        {
            alignas(void*) void* dlopen;
            alignas(void*) char* name;
            alignas(void*) int flags;
            alignas(void*) void* handle;
        };

        struct remote_dlclose_args
        {
            alignas(void*) void* dlclose;
            alignas(void*) void* handle;
        };
    }

    template<typename Target>
    class injector
    {
        using remote_ptr = inject::remote_ptr<Target>;
        using ptrace = inject::ptrace<Target>;
        using remote = inject::remote<Target>;

        using libs_list = std::list<remote_ptr>;
        using libs_list_iterator = typename libs_list::iterator;

    public:

        class handle
        {
            friend class injector;
        public:
            ~handle()
            {
                if(_au)
                    remove();
            }

            bool auto_unlink() const noexcept
            {
                return _au;
            }
            void auto_unlink(bool value) noexcept
            {
                _au = value;
            }

            void remove()
            {
                _inj.remove(*this);
            }

        private:
            handle(injector& inj, libs_list_iterator it, bool auto_unlink_ = false)
                : _inj{inj}, _it{it}, _au{auto_unlink_} {}

            injector& _inj;
            libs_list_iterator _it;
            bool _au;
        };

        explicit injector(const process::process& proc)
            : _proc{proc}
        {
            std::regex libc{".*libc-.*"};
            _addr.malloc = proc.get("malloc", libc).value;
            _addr.free = proc.get("free", libc).value;
            _addr.dlopen = proc.get("__libc_dlopen_mode", libc).value;
            _addr.dlclose = proc.get("__libc_dlclose", libc).value;
            _addr.mmap = proc.get("mmap", libc).value;
            _addr.munmap = proc.get("munmap", libc).value;
            _addr.clone = proc.get("clone", libc).value;
        }

        handle inject(const std::string& path, bool auto_unlink = false)
        {
            ptrace pt{_proc.pid()};
            remote rem{pt};

            auto call_dlopen_addr = rem.mmap(nullptr, Target::remote_dlopen_impl_size(),
                                             PROT_EXEC | PROT_READ,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                             _addr.mmap, _addr.munmap);
            pt.write(Target::remote_dlopen_impl_ptr(), call_dlopen_addr, Target::remote_dlopen_impl_size());
            auto call_dlopen_stack = rem.mmap(nullptr, PAGE_SIZE,
                                              PROT_WRITE | PROT_READ,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                              _addr.mmap, _addr.munmap);
            auto r_lib = rem.malloc(path.size() + 1, _addr.malloc, _addr.free);
            pt.write(path.c_str(), r_lib, path.size() + 1);

            _detail::remote_dlopen_args args = {
                _addr.dlopen.template ptr<void>(),
                r_lib.template ptr<char>(),
                RTLD_LAZY,
                nullptr
            };
            auto r_args = rem.malloc(sizeof(args), _addr.malloc, _addr.free);
            pt.write(&args, r_args, sizeof(args));

            auto r_clone =
                    rem.template function<int(remote_ptr, remote_ptr, int, remote_ptr, remote_ptr, remote_ptr, remote_ptr)>
                            (_addr.clone);
            r_clone(call_dlopen_addr, call_dlopen_stack.get() + PAGE_SIZE,
                    CLONE_SIGHAND | CLONE_FS | CLONE_VM | CLONE_FILES | CLONE_VFORK,
                    r_args, nullptr, nullptr, nullptr);
            pt.read(r_args, &args, sizeof(args));

            _libs.push_front(args.handle);

            return handle{*this, _libs.begin(), auto_unlink};
        }

        void remove(handle& h)
        {
            h.auto_unlink(false);
            remove(h._it);
        }

    private:

        void remove(libs_list_iterator it)
        {
            remote_ptr lib = *it;
            _libs.erase(it);
            remove(lib);
        }

        void remove(remote_ptr lib)
        {
            ptrace pt{_proc.pid()};
            remote rem{pt};

            auto call_dlclose_addr = rem.mmap(nullptr, Target::remote_dlclose_impl_size(),
                                              PROT_EXEC | PROT_READ,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                              _addr.mmap, _addr.munmap);
            pt.write(Target::remote_dlclose_impl_ptr(), call_dlclose_addr, Target::remote_dlclose_impl_size());
            auto call_dlclose_stack = rem.mmap(nullptr, PAGE_SIZE,
                                               PROT_WRITE | PROT_READ,
                                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                               _addr.mmap, _addr.munmap);

            _detail::remote_dlclose_args args = {
                    _addr.dlclose.template ptr<void>(),
                    lib.template ptr<void>()
            };
            auto r_args = rem.malloc(sizeof(args), _addr.malloc, _addr.free);
            pt.write(&args, r_args, sizeof(args));

            auto r_clone =
                    rem.template function<int(remote_ptr, remote_ptr, int, remote_ptr, remote_ptr, remote_ptr, remote_ptr)>
                            (_addr.clone);
            r_clone(call_dlclose_addr, call_dlclose_stack.get() + PAGE_SIZE,
                    CLONE_SIGHAND | CLONE_FS | CLONE_VM | CLONE_FILES | CLONE_VFORK,
                    r_args, nullptr, nullptr, nullptr);
        }

        const process::process& _proc;
        libs_list _libs;
        struct
        {
            remote_ptr malloc;
            remote_ptr free;
            remote_ptr dlopen;
            remote_ptr dlclose;
            remote_ptr mmap;
            remote_ptr munmap;
            remote_ptr clone;
        } _addr;
    };
}

#endif