#ifndef DYNTRACE_TRACER_HPP_
#define DYNTRACE_TRACER_HPP_

#include "dyntrace/arch/arch.hpp"

#include <functional>

namespace dyntrace::tracer
{
    using tracepoint_handler = std::function<void(const void*, const dyntrace::arch::regs&)>;
}

#define DYNTRACE_CREATE_HANDLER(args)\
    extern "C" dyntrace::tracer::tracepoint_handler create_handler(const std::vector<std::string>& args)

#define DYNTRACE_HANDLER(code_arg, regs_arg, ...) [__VA_ARGS__](const void* code_arg, const dyntrace::arch::regs& regs_arg) -> void

#endif