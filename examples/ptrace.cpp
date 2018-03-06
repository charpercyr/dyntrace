#include "dyntrace/inject/executor.hpp"
#include "dyntrace/util/path.hpp"

#include <iostream>
#include <thread>

using namespace std;
using namespace dyntrace::inject;

int main(int argc, const char* argv[])
{
    executor e{dyntrace::find_process("loop")};
    auto f = e.create<void(int)>("print");
    for(int i = 0; i < 10; ++i)
    {
        f(i);
    }

    return 0;
}