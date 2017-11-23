#ifndef DYNTRACE_FASTTP_ARCH_ASM_HPP_
#define DYNTRACE_FASTTP_ARCH_ASM_HPP_

#ifdef __x86_64__
#include "x86_64/asm.hpp"
#else
#error "Architecture not supported"
#endif

#endif