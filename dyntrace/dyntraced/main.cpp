
#include <iostream>

#include <dlfcn.h>
#include <sys/mman.h>

#include <inject/injector.hpp>

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

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        usage(argv[0], 1);
    }

    pid_t pid = find_process(argv[1]);
    process::process proc{pid};
    inject::injector<inject::target::x86_64> inj{proc};

    inj.inject(realpath(argv[2]));

    return 0;
}
