#include "dyntrace/inject/injector.hpp"
#include "dyntrace/util/path.hpp"

#include <iostream>

using namespace std;
using namespace dyntrace::inject;

constexpr auto path = "/opt/dyntrace/lib/dyntrace/libdyntrace-agent.so";

int main(int argc, const char* argv[])
{
    injector inj{dyntrace::find_process("loop")};
    inj.inject(path);
    return 0;
}