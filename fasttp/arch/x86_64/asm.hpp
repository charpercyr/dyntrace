#ifndef DYNTRACE_FASTTP_ARCH_X86_64_ASM_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_ASM_HPP_

#include <cstdint>
#include <vector>

#include <fasttp/code_allocator.hpp>

#include <capstone.h>

namespace dyntrace::fasttp
{
    constexpr size_t branch_size = 5;

    void safe_store(void* to, uintptr_t data);
    void print_branch(void *target, void *to);
    code_allocator::unique_ptr print_handler(code_allocator& alloc, void* func, void* ret, void* handler, const std::vector<uint8_t>& out_of_line);

    csh create_csh();
}

#endif