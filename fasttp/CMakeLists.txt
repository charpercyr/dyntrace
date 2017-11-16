include(arch/${arch}/arch_src.cmake)

add_library(fasttp SHARED
    arch/asm.hpp
    ${${arch}_src}
    code_allocator.cpp code_allocator.hpp
    error.hpp
    fasttp.cpp fasttp.hpp)
target_include_directories(fasttp PRIVATE ${CAPSTONE_INCLUDE_DIRS})
target_link_libraries(fasttp process tracer ${CAPSTONE_LIBRARIES})