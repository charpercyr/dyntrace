#include "dyntrace/arch/arch.hpp"

#include <functional>
#include <string>

using tracer_handler = std::function<void(const void*, const dyntrace::arch::regs& regs)>;

extern "C" tracer_handler create_handler(const std::string& args)
{
    return [](const void* code, const dyntrace::arch::regs& regs)
    {
        printf("Tracepoint at %p\n", code);
    };
}