
#include <iostream>

#include <dlfcn.h>

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

template<typename Arch>
void run(pid_t pid, const char* lib)
{
    using remote_ptr = inject::remote_ptr<Arch>;
    using ptrace = dyntrace::inject::ptrace<Arch>;
    using remote_malloc = inject::remote_function<Arch, remote_ptr(size_t)>;
    using remote_free = inject::remote_function<Arch, void(remote_ptr)>;
    using remote_dlopen = inject::remote_function<Arch, remote_ptr(remote_ptr, int)>;

    process::process proc(pid);
    auto malloc_addr = proc.get("malloc", "libc");
    auto free_addr = proc.get("free", "libc");
    auto dlopen_addr = proc.get("__libc_dlopen_mode", "libc");

    ptrace pt(pid);
    remote_malloc r_malloc{pt, remote_ptr{malloc_addr.value}};
    remote_free r_free{pt, remote_ptr{free_addr.value}};
    remote_dlopen r_dlopen{pt, remote_ptr{dlopen_addr.value}};

    size_t len = strlen(lib) + 1;
    auto rlib = r_malloc(len);
    pt.write(lib, rlib, len);

    r_dlopen(rlib, RTLD_LAZY).get();

    r_free(rlib);
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