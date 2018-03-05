#include "dyntrace/inject/ptrace.hpp"

#include <iostream>
#include <thread>

using namespace std;
using namespace dyntrace::inject;

int main(int argc, const char* argv[])
{
    if(argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <pid>\n";
        exit(1);
    }
    pid_t pid = atoi(argv[1]);

    ptrace pt{pid};

    return 0;
}