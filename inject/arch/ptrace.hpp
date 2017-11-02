#ifndef DYNTRACE_INJECT_ARCH_PTRACE_HPP_
#define DYNTRACE_INJECT_ARCH_PTRACE_HPP_

#ifdef __x86_64__
#include "x86_64/ptrace.hpp"
#else
#error "Architecture not supported"
#endif

#endif