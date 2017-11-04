
#include <iostream>

#include <dlfcn.h>
#include <sys/mman.h>

#include <process/process.hpp>
#include <inject/ptrace.hpp>

#include <unistd.h>

using namespace std;
using namespace dyntrace;

[[noreturn]]
void usage(char* argv0, int code)
{
    ostream& os = (code == 0 ? cout : cerr);
    os << "Usage: " << argv0 << " [name] [lib]" << endl;
    exit(code);
}

struct call_dlopen_args
{
    void*(*func)(const char*, int);
    char* name;
    int mode;
};

extern "C" void* call_dlopen(call_dlopen_args* args)
{
    args->func(args->name, args->mode);
    return NULL;
}

size_t call_dlopen_size()
{
    process::process self(getpid());
    const auto& e = self.elf();
    auto symtab = e.get_section(".symtab").as_symtab();
    for(const auto& sym : symtab)
    {
        if(sym.get_name() == "call_dlopen")
        {
            return sym.get_data().size;
        }
    }
    throw runtime_error("Could not find size");
}

template<typename Arch>
void run(pid_t pid, const char* lib)
{
    using remote_ptr = inject::remote_ptr<Arch>;
    using ptrace = inject::ptrace<Arch>;
    using remote_malloc = inject::remote_function<Arch, remote_ptr(size_t)>;
    using remote_free = inject::remote_function<Arch, void(remote_ptr)>;
    using remote_dlopen = inject::remote_function<Arch, remote_ptr(remote_ptr, int)>;
    using remote_mmap = inject::remote_function<Arch, remote_ptr(remote_ptr, size_t, int, int, int, off_t)>;
    using remote_munmap = inject::remote_function<Arch, int(remote_ptr, size_t)>;
    using remote_clone = inject::remote_function<Arch, int(remote_ptr, remote_ptr, int, remote_ptr, remote_ptr, remote_ptr, remote_ptr)>;
    using remote_waitid = inject::remote_function<Arch, pid_t(int, int, remote_ptr, int)>;

    process::process proc(pid);
    std::regex libc{".*libc.*"};
    auto malloc_addr = proc.get("malloc", libc);
    auto free_addr = proc.get("free", libc);
    auto dlopen_addr = proc.get("__libc_dlopen_mode", libc);
    auto mmap_addr = proc.get("mmap", libc);
    auto munmap_addr = proc.get("munmap", libc);
    auto clone_addr = proc.get("clone", libc);
    auto waitid_addr = proc.get("waitid", libc);

    ptrace pt(pid);
    remote_malloc r_malloc{pt, malloc_addr.value};
    remote_free r_free{pt, free_addr.value};
    remote_dlopen r_dlopen{pt, dlopen_addr.value};
    remote_mmap r_mmap{pt, mmap_addr.value};
    remote_munmap r_munmap{pt, munmap_addr.value};
    remote_clone r_clone{pt, clone_addr.value};
    remote_waitid r_waitid{pt, waitid_addr.value};

    auto call_dlopen_addr = r_mmap(nullptr, call_dlopen_size(),
                                   PROT_EXEC | PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pt.write(reinterpret_cast<void*>(call_dlopen), call_dlopen_addr, call_dlopen_size());
    auto call_dlopen_stack = r_mmap(nullptr, PAGE_SIZE,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    size_t lib_size = strlen(lib) + 1;
    auto r_lib = r_malloc(lib_size);
    pt.write(lib, r_lib, lib_size);

    call_dlopen_args args = {
        r_dlopen.ptr().template ptr<void*(const char*, int)>(),
        r_lib.template ptr<char>(),
        RTLD_LAZY
    };
    auto r_args = r_malloc(sizeof(call_dlopen_args));
    pt.write(&args, r_args, sizeof(call_dlopen_args));

    pid_t r_pid = r_clone(call_dlopen_addr, call_dlopen_stack + PAGE_SIZE,
            CLONE_SIGHAND | CLONE_FS | CLONE_VM | CLONE_FILES | CLONE_VFORK,
            r_args, nullptr, nullptr, nullptr);

    r_munmap(call_dlopen_addr, call_dlopen_size());
    r_munmap(call_dlopen_stack, PAGE_SIZE);
    r_free(r_lib);
    r_free(r_args);
}

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        usage(argv[0], 1);
    }

    pid_t pid = find_process(argv[1]);

    run<inject::x86_64>(pid, argv[2]);

    return 0;
}
