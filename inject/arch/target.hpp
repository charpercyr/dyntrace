#ifndef DYNTRACE_INJECT_ARCH_TARGET_HPP_
#define DYNTRACE_INJECT_ARCH_TARGET_HPP_

#ifdef __x86_64__
#include "inject/arch/x86_64/target.hpp"
#else
#error "Architecture not supported"
#endif

#endif