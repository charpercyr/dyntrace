#include "dyntrace/inject/injector.hpp"
#include "dyntrace/util/path.hpp"

#include <iostream>

using namespace std;
using namespace dyntrace::inject;

constexpr auto path = "/home/christian/Documents/dyntrace/cmake-build-debug/src/dyntrace/agent/libdyntrace-agent.so.0.1";

int main(int argc, const char* argv[])
{
    injector inj{dyntrace::find_process("loop")};
    inj.inject(path);
    return 0;
}