
include(arch/${arch}/arch_src.cmake)

add_library(loader SHARED
        arch/asm.hpp
        ${${arch}_src}
        code_allocator.hpp
        error.hpp
        main.cpp)
target_link_libraries(loader pthread process)