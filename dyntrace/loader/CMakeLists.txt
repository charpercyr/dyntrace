include(arch/${arch}/arch_src.cmake)

add_library(loader SHARED
        arch/asm.hpp
        ${${arch}_src}
        code_allocator.hpp
        error.hpp
        main.cpp)
target_include_directories(loader PRIVATE ${CAPSTONE_INCLUDE_DIRS})
target_link_libraries(loader pthread process tracer ${CAPSTONE_LIBRARIES})