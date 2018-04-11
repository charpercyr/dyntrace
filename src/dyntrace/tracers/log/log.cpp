#include "dyntrace/tracer.hpp"

#include <fstream>
#include <iostream>
#include <memory>

using namespace dyntrace::tracer;

extern "C" point_handler create_point_handler(const std::vector<std::string>& args)
{
    std::shared_ptr<std::ostream> file;
    if(args.empty())
    {
#ifdef _DEBUG
        file = std::shared_ptr<std::ostream>(&std::cout, [](std::ostream*){});
#else
        throw tracer_error{"log", "Missing file argument"};
#endif
    }
    else
        file = std::make_shared<std::ofstream>(args[0], std::ios::app | std::ios::out);
    if(!*file)
        throw std::runtime_error{"Could not open log file"};
    return [file = std::move(file)](const void* code, const dyntrace::arch::regs&)
    {
        *file << "[log] Tracepoint at " << code << std::endl;
    };
}

extern "C" entry_exit_handler create_entry_exit_handler(const std::vector<std::string>& args)
{
    std::shared_ptr<std::ostream> file;
    if(args.empty())
        file = std::shared_ptr<std::ostream>(&std::cout, [](std::ostream*){});
    else
        file = std::make_shared<std::ofstream>(args[0], std::ios::app | std::ios::out);
    if(!*file)
        throw std::runtime_error{"Could not open log file"};
    return {
        [file](const void* code, const dyntrace::arch::regs&)
        {
            *file << "[log] Entry " << code << std::endl;
        },
        [file](const void* code, const dyntrace::arch::regs&)
        {
            *file << "[log] Exit " << code << std::endl;
        }
    };
}