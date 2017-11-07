#ifndef DYNTRACE_INJECT_ARCH_DL_HPP_
#define DYNTRACE_INJECT_ARCH_DL_HPP_

#ifdef __x86_64__
#include "inject/arch/x86_64/dl.hpp"
#else
#error "Architecture not supported"
#endif

#endif