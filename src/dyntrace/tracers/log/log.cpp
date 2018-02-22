#include "dyntrace/arch/arch.hpp"

#include <fstream>
#include <functional>
#include <iostream>
#include <memory>

using tracer_handler = std::function<void(const void*, const dyntrace::arch::regs& regs)>;

extern "C" tracer_handler create_handler(const std::vector<std::string>& args)
{
    std::shared_ptr<std::ostream> file;
    if(args.empty())
        file = std::shared_ptr<std::ostream>(&std::cout, [](std::ostream*){});
    else
        file = std::make_shared<std::ofstream>(args[0]);
    return [file = std::move(file)](const void* code, const dyntrace::arch::regs& regs)
    {
        *file << "Tracepoint at " << code << "\n";
    };
}