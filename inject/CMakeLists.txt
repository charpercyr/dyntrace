
include(arch/${arch}/arch_src.cmake)

add_library(inject STATIC
        arch/ptrace.hpp
        error.hpp
        ${${arch}_src}
        ptrace.hpp
        remote_util.hpp)
target_link_libraries(inject PUBLIC process util)