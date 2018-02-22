#include "dyntrace/tracer.hpp"

#include <fstream>
#include <iostream>
#include <memory>

DYNTRACE_CREATE_HANDLER(args)
{
    std::shared_ptr<std::ostream> file;
    if(args.empty())
        file = std::shared_ptr<std::ostream>(&std::cout, [](std::ostream*){});
    else
        file = std::make_shared<std::ofstream>(args[0], std::ios::app | std::ios::out);
    if(!*file)
        throw std::runtime_error{"Could not open log file"};
    return DYNTRACE_HANDLER(code,, file = std::move(file))
    {
        *file << "[log] Tracepoint at " << code << std::endl;
    };
}