set(
    x86_src
    arch/x86/buffer_writer.hpp
    arch/x86/code_allocator.cpp arch/x86/code_allocator.hpp
    arch/x86/context.cpp arch/x86/context.hpp
    arch/x86/out_of_line.cpp arch/x86/out_of_line.hpp
    arch/x86/jmp.hpp
    arch/x86/tracepoint.cpp arch/x86/tracepoint.hpp
)

if(SUBARCH STREQUAL x86_64)
    list(APPEND x86_src arch/x86/tracepoint64.S)
endif()