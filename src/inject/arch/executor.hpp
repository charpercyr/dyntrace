#ifndef DYNTRACE_INJECT_ARCH_EXECUTOR_HPP_
#define DYNTRACE_INJECT_ARCH_EXECUTOR_HPP_

#if defined(__i386__) || defined(__x86_64__)
#include "x86/executor.hpp"
#else
#error "Architecture not supported"
#endif

#endif