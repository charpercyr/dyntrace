#ifndef DYNTRACE_FASTTP_TRACEPOINT_ASM_HPP_
#define DYNTRACE_FASTTP_TRACEPOINT_ASM_HPP_

#ifdef __x86_64__
#include "fasttp/arch/x86_64/tracepoint.hpp"
#else
#error "Architecture not supported"
#endif

#endif