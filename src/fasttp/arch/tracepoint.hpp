/**
 * Includes arch-specific files. A user should NOT include this file or use any arch-specific classes.
 */
#ifndef DYNTRACE_FASTTP_TRACEPOINT_ASM_HPP_
#define DYNTRACE_FASTTP_TRACEPOINT_ASM_HPP_

#if defined(__i386__) || defined(__x86_64__)
#include "x86/tracepoint.hpp"
#elif defined(__arm__)
#include "arm/tracepoint.hpp"
#elif defined(__powerpc__) || defined(__powerpc64__)
#include "powerpc/tracepoint.hpp"
#else
#error "Architecture not supported"
#endif

#endif