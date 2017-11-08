
#include <iostream>

#include <dlfcn.h>
#include <sys/mman.h>

#include <inject/remote.hpp>

#include <process/process.hpp>

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

template<typename Target>
void run(pid_t pid, const char* lib)
{
    using remote_ptr = inject::remote_ptr<Target>;
    using ptrace = inject::ptrace<Target>;
    using remote = inject::remote<Target>;

    process::process proc(pid);
    std::regex libc{".*libc.*"};
    auto malloc_addr = proc.get("malloc", libc);
    auto free_addr = proc.get("free", libc);
    auto dlopen_addr = proc.get("__libc_dlopen_mode", libc);
    auto mmap_addr = proc.get("mmap", libc);
    auto munmap_addr = proc.get("munmap", libc);
    auto clone_addr = proc.get("clone", libc);

    ptrace pt{pid};
    remote rem{pt};
    auto r_munmap = rem.template function<int(remote_ptr, size_t)>(munmap_addr.value);
    auto r_clone = rem.template function<int(remote_ptr, remote_ptr, int, remote_ptr, remote_ptr, remote_ptr, remote_ptr)>(clone_addr.value);

    auto call_dlopen_addr = rem.mmap(
        nullptr, call_dlopen_size(),
        PROT_EXEC | PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
        mmap_addr.value, munmap_addr.value);
    pt.write(reinterpret_cast<void*>(call_dlopen), call_dlopen_addr, call_dlopen_size());
    auto call_dlopen_stack = rem.mmap(
        nullptr, PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
        mmap_addr.value, munmap_addr.value);

    size_t lib_size = strlen(lib) + 1;
    auto r_lib = rem.malloc(lib_size, malloc_addr.value, free_addr.value);
    pt.write(lib, r_lib, lib_size);

    call_dlopen_args args = {
        remote_ptr{dlopen_addr.value}.template ptr<void*(const char*, int)>(),
        r_lib.template ptr<char>(),
        RTLD_LAZY
    };
    auto r_args = rem.malloc(sizeof(call_dlopen_args), malloc_addr.value, free_addr.value);
    pt.write(&args, r_args, sizeof(call_dlopen_args));

    pid_t r_pid = r_clone(call_dlopen_addr, call_dlopen_stack.get() + PAGE_SIZE,
        CLONE_SIGHAND | CLONE_FS | CLONE_VM | CLONE_FILES | CLONE_VFORK,
        r_args, nullptr, nullptr, nullptr);
}

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        usage(argv[0], 1);
    }

    pid_t pid = find_process(argv[1]);

    run<inject::target::x86_64>(pid, argv[2]);

    return 0;
}
